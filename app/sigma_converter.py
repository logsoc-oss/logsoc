"""sigma_converter.py — v0.6.5 Sigma AST parser + ClickHouse SQL binder.

Two responsibilities:
  1. parse_detection(detection_dict, condition_str) -> SigmaAST
     Convert a Sigma rule's `detection` block + `condition` expression into
     a structured tree that survives schema changes.
  2. bind_to_clickhouse(ast) -> str
     Render the AST as a ClickHouse WHERE-clause fragment targeting the
     `logsoc.siem_logs` table.

Why an AST instead of pre-compiling to SQL and storing the string? Because
the agent's eBPF events will gain new fields (process ancestry, container
IDs, etc.) over time. When that happens, we update ONE binder function
instead of recompiling every rule's stored SQL.

Supported Sigma operators (this subset covers ~85% of real-world rules):
  - Wildcard equality:    Field|contains: "x"  -> LIKE '%x%'
  - Suffix match:         Field|endswith: "x"  -> LIKE '%x'  (or ENDSWITH)
  - Prefix match:         Field|startswith: "x" -> LIKE 'x%'
  - Regex:                Field|re: "..."      -> match(...)
  - Equality lists:       Field: [a, b]         -> Field IN ('a','b')
  - Equality single:      Field: a              -> Field = 'a'
  - 1/0 flag:             Field: 1              -> Field = 1 (UInt8)
  - Negation:             -selection: {...}     -> NOT(...)
  - And/Or groups:        1 of selection_*      -> ANY of children
                          all of selection_*    -> ALL of children

Unsupported (will raise SigmaUnsupportedFeature):
  - count(), aggregate(), avg(), min() window aggregations
  - near() temporal operator
  - field_ref() (cross-field references like ParentImage/Image)
  - multi-condition expressions like "selection_1 and (selection_2 or selection_3)"

For unsupported rules, the importer stores them anyway with
query_supported=0 so the dashboard can surface them as "needs manual tuning".
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("logsoc.sigma_converter")


# ── Field name mapping: Sigma convention -> our siem_logs column ──
# ClickHouse column name on the LEFT, Sigma field on the RIGHT. The
# Sigma side of MITRE/auditd rules uses PascalCase (e.g. "Image",
# "CommandLine"). The Linux subset uses lowercase + underscores which
# match our schema directly, so most entries are no-ops.
#
# When the Sigma field matches our column directly, no entry is needed.
# Add to this map when a rule uses a Sigma-specific field name.

FIELD_MAP: Dict[str, str] = {
    # Standard Sysmon / auditd fields -> siem_logs columns
    "Image": "comm",
    "ParentImage": "comm",
    "CommandLine": "message",
    "ParentCommandLine": "message",
    "OriginalFileName": "comm",
    "User": "username",
    "CurrentDirectory": "filename",
    "ProcessId": "pid",
    "ParentProcessId": "pid",
    # Linux-specific
    "exe": "comm",
    "cmdline": "message",
    "uid": "uid",
    "cwd": "filename",
    "path": "filename",
    "host": "source_host",
    "host.name": "source_host",
    "destination.ip": "dst_ip",
    "destination.port": "dst_port",
    "event.action": "event",
    "process.name": "comm",
    "process.pid": "pid",
    "process.executable": "comm",
    "process.command_line": "message",
    "process.working_directory": "filename",
    "user.name": "username",
    "user.id": "uid",
    "file.path": "filename",
    "file.name": "filename",
    "log.source": "service",
    "process.parent.name": "comm",
    "process.parent.executable": "comm",
    # Network connection fields (Windows Sysmon / Linux auditd)
    "DestinationIp": "dst_ip",
    "DestinationPort": "dst_port",
    "SourceIp": "source_ip",
    "SourcePort": "message",  # no dedicated column; arg appears in message
    "Protocol": "message",  # no dedicated column; arg appears in message
    "Image": "comm",  # process path/image
    "ProcessGuid": "message",  # no dedicated column
    "ParentProcessGuid": "message",
    # Network flow direction (Sigma "Initiated" field). Our schema doesn't
    # have a dedicated direction column, but the human-readable event text
    # (e.g. "connect", "accept") usually contains a hint. We fall back to
    # the message text; the field name itself doesn't appear in the
    # message, so this is essentially a no-op for short tokens like
    # "true"/"false" — but it keeps the rule compilable and lets the more
    # important CIDR filter do its job.
    "Initiated": "message",
    # Internal marker used by "|all" shorthand: full-text AND on the
    # raw event message. Maps to the same `message` column.
    "__message__": "message",
}


class SigmaUnsupportedFeature(Exception):
    """Raised when a Sigma rule uses a feature we don't support (yet)."""


class SigmaCompileError(Exception):
    """Raised when the AST is well-formed but can't bind to ClickHouse."""


# ── AST node types ──

@dataclass
class SigmaSelection:
    """One named selection block, e.g. 'selection_main: {Image|endswith: ...}'.

    A selection is an AND of all its field constraints. Lists in a binary
    operator (e.g. `endswith: ['/at', '/atd']`) are expanded into N constraints
    that the binder ORs together (Sigma semantics: 'A|endswith: [x,y]' means
    the field ends with x OR y). The constraint tuple is
    `(field, op, value, spread)`: when `spread` is True, multiple constraints
    with the same `(field, op)` are joined with OR inside the selection.
    """
    name: str
    # (field, op, value, spread) where spread is:
    #   True  → multiple same-(field,op) constraints OR-ed together
    #   False → standalone AND term
    #   "all" → multiple same-(field,op) constraints AND-ed together
    #           (Sigma "Field|op|all: [a, b, c]" — every value must match)
    constraints: List[Tuple[str, str, Any, Any]]  # (field, op, value, spread)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "selection",
            "name": self.name,
            "constraints": [
                {"field": f, "op": o, "value": v, "spread": s}
                for f, o, v, s in self.constraints
            ],
        }


@dataclass
class SigmaGroup:
    """A nested '1 of selection_*' or 'all of selection_*' group."""
    quantifier: str  # "any" | "all"
    children: List[str]  # names of selections / nested groups

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "group",
            "quantifier": self.quantifier,
            "children": self.children,
        }


@dataclass
class SigmaExpression:
    """The top-level condition tree (AND/OR/NOT over selections + groups)."""
    operator: str  # "and" | "or" | "not" | "single"
    children: List[Any]  # names of selections or nested SigmaExpression
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out_children = []
        for c in self.children:
            if hasattr(c, "to_dict"):
                out_children.append(c.to_dict())
            else:
                out_children.append(c)
        return {
            "type": "expression",
            "operator": self.operator,
            "children": out_children,
            "raw": self.raw,
        }


@dataclass
class SigmaAST:
    selections: Dict[str, SigmaSelection]
    expression: SigmaExpression
    detection: SigmaExpression  # alias of expression (kept for clarity)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "selections": {k: v.to_dict() for k, v in self.selections.items()},
            "expression": self.expression.to_dict(),
        }


# ── Constraint operators ──

# Mapping Sigma field-suffix operators to our internal op names.
# Two-arg operator "contains|all" is mapped to a marker; the selection
# parser sees it and emits an AND-of-contains at bind time.
SIGMA_OP_MAP: Dict[str, str] = {
    "contains": "contains",
    "icontains": "icontains",
    "startswith": "startswith",
    "endswith": "endswith",
    "re": "regex",
    "equals": "equals",
    "fieldref": "fieldref",
    "contains|all": "contains_all",  # AND-of-contains (every value must be present)
    "startswith|all": "startswith_all",
    "endswith|all": "endswith_all",
    "equals|all": "equals_all",
    "cidr": "cidr",  # network range: Field|cidr: ["10.0.0.0/8"] → IN-range check
}

# Operators that mean the same thing as the bare field (no suffix).
NOP_SUFFIX = {"all"}


def _parse_field_spec(field_key: str) -> Tuple[str, Optional[str]]:
    """Parse 'Image|endswith' -> ('Image', 'endswith'). 'cmdline' -> ('cmdline', None).

    Returns (field_name, op). The op is one of:
      - None: bare field (no operator suffix)
      - 'equals', 'contains', 'startswith', 'endswith', 'regex': known operators
      - 'all': Sigma "match all values" modifier (Field|all: [a,b] = AND)
        — currently unsupported, will be flagged by the parse_selection caller
      - Any other string: unknown operator, treated as unsupported
    """
    if "|" not in field_key:
        return field_key, None
    field, op = field_key.split("|", 1)
    if op == "all":
        # 'Field|all: [a, b]' is a Sigma modifier meaning "field matches all
        # values" (semantic AND over the values). Bare '|all: [a, b]' (no
        # field name) is a shorthand for full-text AND over the event message.
        # Both are supported in T4 by emitting an AND-of-LIKE inside the
        # selection; the parser turns them into a list of `_all`-flagged
        # constraints (see _parse_selection_block).
        if field == "":
            return "__message__", "all"  # marker: full-text AND on message
        return field, "all"  # marker: AND on this field
    if op in NOP_SUFFIX:
        return field, None
    op_norm = SIGMA_OP_MAP.get(op, op)
    if op_norm not in SIGMA_OP_MAP.values() and op_norm != "fieldref":
        # Unknown operator — let it through and let the binder complain
        pass
    return field, op_norm


# ── Detection parser ──

def _parse_selection_block(name: str, block: Any) -> SigmaSelection:
    """Parse a single 'selection_xxx: {Field|op: value, ...}' block.

    Accepts a dict (canonical form) or a list (Sigma sugar: a list at the
    block top-level means "match if any value matches" — equivalent to
    `{Field: [values]}` against a synthetic `*` field, which we render as
    a `contains` on the `message` column).
    """
    # Sugar: a bare list as a selection means "any of these values appears
    # in the message". Sigma treats this as OR-equality against a hidden
    # field, and many authors use it for keyword-style filters.
    if isinstance(block, list):
        if not block:
            raise SigmaUnsupportedFeature(f"selection '{name}' is an empty list")
        return SigmaSelection(
            name=name,
            constraints=[("message", "contains", v, True) for v in block],
        )
    if not isinstance(block, dict):
        raise SigmaUnsupportedFeature(f"selection '{name}' is not a dict or list")
    # Group constraints by (field, op). Multiple entries for the same
    # (field, op) pair become a single OR-grouped constraint in the
    # rendered SQL (this is how Sigma "list values on a binary operator"
    # are interpreted: e.g. `endswith: ['/at', '/atd']` = field ends with
    # /at OR /atd).
    #
    # `_ALL_OPS` is a parallel OR-list but joined with AND in SQL — these
    # are the `Field|op|all: [a, b, c]` Sigma modifiers, meaning "every
    # value must be present" (semantic AND-of-contains).
    _ALL_OPS = {"contains_all", "startswith_all", "endswith_all", "equals_all"}
    constraints: List[Tuple[str, str, Any, bool]] = []
    for field_key, value in block.items():
        if field_key.startswith("_"):
            continue  # comment / metadata
        field_name, op = _parse_field_spec(field_key)
        # Bare field with list value: Sigma semantics are OR-of-equality
        if op is None:
            if isinstance(value, list):
                for v in value:
                    constraints.append((field_name, "equals", v, True))
                continue
            else:
                op = "equals"
        # "Op|all" modifiers (contains|all, etc.) with a list: AND-of-op
        # (every value must match the field). We expand into N constraints
        # marked with a special flag; the binder joins them with AND.
        if op in _ALL_OPS and isinstance(value, list):
            # Strip the "_all" suffix so _bind_constraint receives the
            # underlying op ("contains", "startswith", ...).
            base_op = op.replace("_all", "")
            for v in value:
                constraints.append((field_name, base_op, v, "all"))
            continue
        # "Field|all" or bare "|all" with a list: full-text AND over the
        # event (or a specific field). Sigma semantic: "every value must
        # appear" in the field/message. We emit N LIKE constraints AND-ed.
        if op == "all" and isinstance(value, list):
            target_field = "__message__" if field_name == "__message__" else field_name
            for v in value:
                constraints.append((target_field, "contains", v, "all"))
            continue
        # Binary string operators with a list: expand into N constraints
        # marked as "spread" — they'll be OR-ed by the binder.
        if op in ("endswith", "contains", "icontains", "startswith") and isinstance(value, list):
            for v in value:
                constraints.append((field_name, op, v, True))
            continue
        # 'equals' with a list: this is "Field: [a, b]" = OR
        if op == "equals" and isinstance(value, list):
            for v in value:
                constraints.append((field_name, "equals", v, True))
            continue
        constraints.append((field_name, op, value, False))
    if not constraints:
        raise SigmaUnsupportedFeature(f"selection '{name}' is empty")
    return SigmaSelection(name=name, constraints=constraints)


def _build_top_expression(condition: str, selection_names: Set[str]) -> SigmaExpression:
    """Parse 'condition: selection_1 and not selection_2' into a SigmaExpression.

    Supports: and, or, not, parentheses, plain identifiers, "1 of", "all of",
    "<n> of". Anything else raises SigmaUnsupportedFeature.
    """
    raw = condition.strip()
    if not raw:
        # No condition = implicit AND of all selections
        names = sorted(selection_names)
        return SigmaExpression(
            operator="and",
            children=names,
            raw=raw,
        )

    # Quick reject for features we don't parse (yet)
    forbidden = ["near(", "count(", "aggregate(", "fieldref(", "min(", "max(", "avg("]
    for f in forbidden:
        if f in raw.lower():
            raise SigmaUnsupportedFeature(f"condition uses unsupported feature: {f}")

    tokens = _tokenize_condition(raw)
    expr = _parse_or(tokens, selection_names)
    if tokens:
        raise SigmaUnsupportedFeature(f"unparsed condition tail: {' '.join(tokens)}")
    return expr


def _tokenize_condition(cond: str) -> List[str]:
    """Tokenize a Sigma condition expression.

    'selection_1 and not (selection_2 or selection_3)' ->
    ['selection_1', 'and', 'not', '(', 'selection_2', 'or', 'selection_3', ')']
    """
    cond = cond.strip()
    out: List[str] = []
    i = 0
    while i < len(cond):
        c = cond[i]
        if c.isspace():
            i += 1
            continue
        if c in "()":
            out.append(c)
            i += 1
            continue
        # multi-char operator
        if cond[i:i+3] == "and" and (i+3 == len(cond) or not cond[i+3].isalnum() and cond[i+3] != "_"):
            out.append("and")
            i += 3
            continue
        if cond[i:i+2] == "or" and (i+2 == len(cond) or not cond[i+2].isalnum() and cond[i+2] != "_"):
            out.append("or")
            i += 2
            continue
        if cond[i:i+3] == "not" and (i+3 == len(cond) or not cond[i+3].isalnum() and cond[i+3] != "_"):
            out.append("not")
            i += 3
            continue
        # identifier
        j = i
        while j < len(cond) and not cond[j].isspace() and cond[j] not in "()":
            j += 1
        out.append(cond[i:j])
        i = j
    return out


def _parse_or(tokens: List[str], names: Set[str]) -> SigmaExpression:
    left = _parse_and(tokens, names)
    while tokens and tokens[0] == "or":
        tokens.pop(0)
        right = _parse_and(tokens, names)
        left = SigmaExpression(operator="or", children=[left, right], raw="or")
    return left


def _parse_and(tokens: List[str], names: Set[str]) -> SigmaExpression:
    left = _parse_unary(tokens, names)
    children = [left]
    while tokens and tokens[0] == "and":
        tokens.pop(0)
        right = _parse_unary(tokens, names)
        children.append(right)
    if len(children) == 1:
        return left
    return SigmaExpression(operator="and", children=children, raw="and")


def _parse_unary(tokens: List[str], names: Set[str]) -> SigmaExpression:
    if not tokens:
        raise SigmaUnsupportedFeature("empty condition")
    if tokens[0] == "not":
        tokens.pop(0)
        inner = _parse_unary(tokens, names)
        return SigmaExpression(operator="not", children=[inner], raw="not")
    if tokens[0] == "(":
        tokens.pop(0)
        expr = _parse_or(tokens, names)
        if not tokens or tokens[0] != ")":
            raise SigmaUnsupportedFeature("missing closing paren")
        tokens.pop(0)
        return expr
    # Plain identifier (selection name, or a quantifier like "1 of selection_*")
    ident = tokens.pop(0)
    if ident in names:
        return SigmaExpression(operator="single", children=[ident], raw=ident)
    # Quantifiers: "1 of foo_*", "all of foo_*", "any of foo_*"
    m = re.match(r"^(\d+|all|any)$", ident, re.IGNORECASE)
    if m and tokens and tokens[0] == "of":
        tokens.pop(0)
        # Collect wildcard prefix(es) — Sigma allows "1 of selection_a or selection_b"
        prefixes: List[str] = []
        prefixes.append(tokens.pop(0))
        while tokens and tokens[0] == "or":
            # 'or' between prefixes is the only Sigma-supported separator here
            tokens.pop(0)
            prefixes.append(tokens.pop(0))
        matched: List[str] = []
        for prefix in prefixes:
            if prefix.endswith("*"):
                for n in sorted(names):
                    if n.startswith(prefix[:-1]):
                        matched.append(n)
            elif prefix in names:
                matched.append(prefix)
            else:
                raise SigmaUnsupportedFeature(f"quantifier target {prefix!r} matches no selection")
        quant = "any" if ident.lower() in ("any", "1") else "all"
        if quant == "any" and len(matched) == 0:
            return SigmaExpression(operator="false_", children=[], raw=ident)
        if quant == "any" and len(matched) == 1:
            return SigmaExpression(operator="single", children=matched, raw=ident)
        return SigmaExpression(operator=quant, children=matched, raw=ident)
    raise SigmaUnsupportedFeature(f"unrecognized condition token: {ident!r}")


def parse_detection(detection: Dict[str, Any], condition: str = "") -> SigmaAST:
    """Public entry: parse a Sigma `detection` block into a SigmaAST."""
    if not isinstance(detection, dict) or not detection:
        raise SigmaUnsupportedFeature("detection block is empty or not a dict")
    selections: Dict[str, SigmaSelection] = {}
    # Some Sigma authors mistakenly embed `condition:` inside the detection
    # block (it belongs at the YAML top level). Strip it and use it as the
    # top-level condition if none was passed in.
    detection = dict(detection)  # don't mutate caller's dict
    if "condition" in detection and not condition:
        condition = detection.pop("condition") or ""
    else:
        detection.pop("condition", None)  # always strip, even if condition is set
    # Parse every selection block first. If any one raises, the whole rule
    # is rejected — we never want a partial import where the condition
    # references a selection we didn't register.
    parsed: Dict[str, SigmaSelection] = {}
    for name, block in detection.items():
        if not isinstance(block, dict) and not isinstance(block, list):
            continue
        # Filter: only top-level "selection_*" or "filter_*" or named
        # blocks. Sigma convention: 'selection', 'selection_*', 'filter',
        # 'filter_*', 'timeframe', 'count'.
        if name in ("timeframe", "count", "aggregate"):
            raise SigmaUnsupportedFeature(
                f"detection uses {name!r} (temporal/aggregate rules are out of scope for T4)"
            )
        parsed[name] = _parse_selection_block(name, block)
    selections = parsed
    if not selections:
        raise SigmaUnsupportedFeature("no valid selection blocks parsed")
    names = set(selections.keys())
    expr = _build_top_expression(condition, names)
    return SigmaAST(selections=selections, expression=expr, detection=expr)


# ── ClickHouse SQL binder ──

def _bind_constraint(field: str, op: str, value: Any) -> str:
    """Render a single (field, op, value) constraint as a SQL fragment."""
    col = FIELD_MAP.get(field, field)
    # Safe column whitelist — reject any column not in our schema
    if col not in _SAFE_COLUMNS:
        # Fallback: search the full event message text. This is a noisy
        # match (the field name itself isn't tokenized in the message),
        # but it's better than emitting 0=1 which kills the rule entirely.
        # For auditd fields (a0..a3, cmd, etc.) the args appear in the
        # human-readable event text, so contains/equals both work in
        # practice for short tokens like 'iptables' or 'getcap'.
        # We only fall back for `equals`/`contains`/`endswith`/`startswith` —
        # structural operators like `regex` still need a real column.
        if op in ("equals", "contains", "icontains", "endswith", "startswith"):
            return _bind_constraint("message", op, value)
        logger.debug("Skipping unknown Sigma field %r -> %r (op %r)", field, col, op)
        return "0=1"

    if op in ("equals", "fieldref"):
        return _bind_equality(col, value)
    if op == "cidr":
        # Network range check. ClickHouse has `isIPAddressInRange(col, cidr)`
        # which handles both IPv4 and IPv6, but the input column must be the
        # canonical text form ('10.1.2.3' or '::1'). Our IP columns are
        # Strings but often EMPTY (most events aren't network flows), and
        # isIPAddressInRange('', '10.0.0.0/8') throws CANNOT_PARSE_TEXT.
        # Guard with `col != ''` so empty values are excluded (they can
        # never match a CIDR anyway).
        def _quote_cidr(c: str) -> str:
            return "'" + str(c).replace("'", "''") + "'"
        if isinstance(value, list):
            parts = [f"({col} != '' AND isIPAddressInRange({col}, {_quote_cidr(c)}))" for c in value]
            return "(" + " OR ".join(parts) + ")"
        return f"({col} != '' AND isIPAddressInRange({col}, {_quote_cidr(value)}))"
    if op in ("contains", "icontains"):
        if not isinstance(value, str):
            value = str(value)
        # ClickHouse uses '\' as the default LIKE escape char and does NOT
        # support the SQL-standard `ESCAPE '!'` clause. So we escape the
        # wildcards ('%' and '_') and the escape char itself with a single
        # backslash, then single-quote the result with ' doubling.
        needle = value.replace("\\", "\\\\").replace("'", "''").replace("%", "\\%").replace("_", "\\_")
        return f"{col} ILIKE '%{needle}%'" if op == "icontains" else f"{col} LIKE '%{needle}%'"
    if op == "startswith":
        if not isinstance(value, str):
            value = str(value)
        needle = value.replace("\\", "\\\\").replace("'", "''").replace("%", "\\%").replace("_", "\\_")
        return f"{col} LIKE '{needle}%'"
    if op == "endswith":
        if not isinstance(value, str):
            value = str(value)
        needle = value.replace("\\", "\\\\").replace("'", "''").replace("%", "\\%").replace("_", "\\_")
        return f"{col} LIKE '%{needle}'"
    if op == "regex":
        if not isinstance(value, str):
            raise SigmaCompileError(f"regex value must be string, got {type(value).__name__}")
        # ClickHouse: match(needle, haystack) — using match() for partial regex
        return f"match({col}, '{value}')"
    if op == "in":
        if not isinstance(value, list):
            value = [value]
        rendered = []
        for v in value:
            if isinstance(v, (int, float)):
                rendered.append(str(v))
            else:
                sval = str(v).replace("\\", "\\\\").replace("'", "''")
                rendered.append(f"'{sval}'")
        return f"{col} IN ({', '.join(rendered)})"
    raise SigmaCompileError(f"unsupported operator: {op}")


def _bind_equality(col: str, value: Any) -> str:
    if isinstance(value, bool):
        return f"{col} = {1 if value else 0}"
    if isinstance(value, (int, float)):
        return f"{col} = {value}"
    if isinstance(value, str):
        sval = value.replace("\\", "\\\\").replace("'", "\\'")
        return f"{col} = '{sval}'"
    if isinstance(value, list):
        # Should have been caught upstream as 'in', but be safe
        return _bind_constraint(col, "in", value)
    raise SigmaCompileError(f"unsupported equality value: {value!r}")


def _bind_selection(sel: SigmaSelection) -> str:
    """A selection is the AND of all its constraints, with each constraint
    optionally being a spread (OR of N values for the same field+op pair).

    The parser pre-expanded list values into N entries with `spread=True` on
    each. We group consecutive entries with `spread=True` AND sharing the
    same (field, op) and OR them; everything else is a plain AND.
    """
    # Walk the constraints, collecting:
    #  - runs of (field, op, value) with spread=True sharing the same (field, op)
    #  - runs with spread="all" — joined with AND (Sigma `op|all` modifier)
    #  - single constraints (spread=False) which are individual AND terms
    parts: List[str] = []
    i = 0
    while i < len(sel.constraints):
        field, op, value, spread = sel.constraints[i]
        if (spread is True or spread == "all") and (i + 1) < len(sel.constraints) and sel.constraints[i + 1][3] == spread:
            # Look ahead: collect all consecutive constraints with the
            # same (field, op) and same spread flag.
            j = i
            values: List[Any] = []
            while (
                j < len(sel.constraints)
                and sel.constraints[j][0] == field
                and sel.constraints[j][1] == op
                and sel.constraints[j][3] == spread
            ):
                values.append(sel.constraints[j][2])
                j += 1
            sub = [_bind_constraint(field, op, v) for v in values]
            joiner = " AND " if spread == "all" else " OR "
            parts.append("(" + joiner.join(sub) + ")")
            i = j
        else:
            parts.append(f"({_bind_constraint(field, op, value)})")
            i += 1
    if not parts:
        return "1=1"
    return "(" + " AND ".join(parts) + ")"


def _bind_expression(
    expr: SigmaExpression,
    selections: Dict[str, SigmaSelection],
) -> str:
    """Recursively render an expression node."""
    if expr.operator == "single":
        name = expr.children[0]
        if name not in selections:
            raise SigmaCompileError(f"unknown selection: {name}")
        return _bind_selection(selections[name])
    if expr.operator == "not":
        return f"NOT ({_bind_expression(expr.children[0], selections)})"
    if expr.operator == "and":
        return "(" + " AND ".join(_bind_expression(c, selections) for c in expr.children) + ")"
    if expr.operator == "or":
        return "(" + " OR ".join(_bind_expression(c, selections) for c in expr.children) + ")"
    if expr.operator == "any":
        sub = [_bind_selection(selections[n]) for n in expr.children if n in selections]
        if not sub:
            return "1=0"
        return "(" + " OR ".join(sub) + ")"
    if expr.operator == "all":
        sub = [_bind_selection(selections[n]) for n in expr.children if n in selections]
        if not sub:
            return "1=0"
        return "(" + " AND ".join(sub) + ")"
    if expr.operator == "false_":
        return "1=0"
    raise SigmaCompileError(f"unknown expression operator: {expr.operator}")


# Safe-column whitelist: ONLY fields we know exist in siem_logs.
# If a Sigma rule references a field not here, the binder emits 0=1
# (no match) to avoid false positives on broken rules.
_SAFE_COLUMNS: Set[str] = {
    "received_at", "agent_id", "source_host", "source_ip", "service",
    "severity", "message", "raw_message", "tags", "event", "event_id",
    "comm", "username", "filename", "pid", "uid", "dst_ip", "dst_port",
    "inode", "os_name", "os_version", "kernel_version", "agent_version",
    "host_ips", "journald_match", "journald_message", "journald_unit",
    "journald_identifier", "ebpf_match", "ebpf_event", "ebpf_comm",
    "ebpf_filename", "correlation_window_ms",
}


def bind_to_clickhouse(ast: SigmaAST) -> str:
    """Render the AST top expression as a ClickHouse WHERE fragment."""
    if not isinstance(ast, SigmaAST):
        raise SigmaCompileError(f"expected SigmaAST, got {type(ast).__name__}")
    sql = _bind_expression(ast.expression, ast.selections)
    if not sql or sql.strip() == "":
        raise SigmaCompileError("binder produced empty SQL")
    # Reject SQL that is dead-on-arrival: any `0=1` literal (anywhere, with
    # any parens around it) means at least one selection referenced a
    # column we don't know about. The caller (importer) will record this
    # as unsupported. Without this check we'd insert rules that look
    # "compiled" but never match anything — a silent failure for SOC
    # analysts.
    import re as _re
    if _re.search(r"\b0\s*=\s*1\b", sql):
        raise SigmaUnsupportedFeature(
            "compiled SQL contains 0=1 placeholder (at least one Sigma field is unmapped)"
        )
    return sql
