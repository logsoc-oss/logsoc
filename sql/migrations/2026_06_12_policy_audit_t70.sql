-- T70 / Policy Audit Log (v0.21.0-t70)
-- 2026-06-12
--
-- Audit log des changements sur la table `agent_policy` (T64 + T64.6).
-- Pattern append-only : trigger AFTER INSERT/UPDATE/DELETE capture OLD/NEW
-- en JSON, jamais muté après. Sibling de `gdpr_audit` (T67) et
-- `compliance_audit` (T58).
--
-- Use cases :
--  - "Qui a changé la bind address à 0.0.0.0 sur srv-demo-core et quand ?"
--  - "Quels agents ont reçu un override cette semaine ?"
--  - "Historique complet des seuils YaraShipper"
--  - Compliance RGPD art. 5(2) : traçabilité des changements de config
--
-- Rétention : alignée sur compliance_audit (1095j = 3y, défaut
-- tools/purge_old_audit.py, T68). Pas de colonne `retention_days`
-- custom pour KISS — purge_old_audit.py T68 étendu dans une
-- migration ultérieure si besoin.

-- ── PITFALL MariaDB errno 150 (FK incorrectly formed) ───────────────
-- Symptôme : `Can't create table (errno: 150 "Foreign key constraint
-- is incorrectly formed")` même quand la collation de la table
-- matche. Cause réelle : INCOMPATIBILITÉ DE TYPE entre la colonne FK
-- et la colonne référencée. `users.id` est `INT(11) NOT NULL` (pas
-- BIGINT), donc `updated_by BIGINT` ne peut pas avoir de FK vers
-- `users.id`. MariaDB exige un type exact ou un type compatible
-- (signed/unsigned + display width + ON UPDATE/DELETE).
--
-- Solution KISS : pas de FK, garder `updated_by` en `BIGINT NULL`
-- (cohérent avec `agent_policy.updated_by` BIGINT loose, et
-- `compliance_audit`/`gdpr_audit` qui n'ont pas de FK vers users).
-- L'app fait le JOIN en SQL via `users.id` quand l'UI affiche
-- "qui a fait quoi". Tradeoff : intégrité référentielle déplacée
-- au niveau applicatif (mais c'est un audit, pas une donnée vitale).
--
-- Variante alternative non retenue : changer `updated_by` en `INT`
-- pour avoir la FK. Refusé pour 2 raisons :
--   1. Risque de dépassement (BILLIONS d'updates — non, pas réaliste,
--      mais on garde la cohérence de type avec `agent_policy`)
--   2. `agent_policy.updated_by` reste BIGINT loose, donc avoir 2
--      conventions dans le même sous-domaine est confus
--
-- Note collation : `users` est en `utf8mb4_uca1400_ai_ci` (server
-- default MariaDB 11.4), `agent_policy`/`compliance_audit`/
-- `gdpr_audit` sont en `utf8mb4_unicode_ci`. Pour policy_audit on
-- force `utf8mb4_unicode_ci` pour matcher nos tables sœurs (sans
-- FK, c'est juste pour la cohérence applicative).

-- ── Table policy_audit (append-only) ─────────────────────────────────
-- Pattern : 1 row par mutation de agent_policy. OLD/NEW en JSON pour
-- garder le diff complet (pas juste les valeurs finales). action
-- enum pour faciliter les filtres de la route GET.
CREATE TABLE IF NOT EXISTS policy_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    -- Scope de la mutation. NULL = la row globale (T64.6 agent_id=NULL).
    -- Sinon = UUID de l'agent (per-agent override created/updated/deleted).
    agent_id VARCHAR(64) NULL,
    -- Action : 'insert' | 'update' | 'delete' (même sémantique que les
    -- triggers standards). 'insert' = nouvelle row (global seed OU
    -- per-agent override created). 'update' = PUT global OU PUT
    -- per-agent (update path). 'delete' = DELETE per-agent uniquement
    -- (la row globale n'est jamais supprimée).
    action ENUM('insert', 'update', 'delete') NOT NULL,
    -- OLD row en JSON. NULL pour 'insert' (pas de OLD).
    old_values JSON NULL,
    -- NEW row en JSON. NULL pour 'delete' (pas de NEW).
    new_values JSON NULL,
    -- User qui a fait la mutation. NULL si système (auto-seed).
    updated_by BIGINT NULL,
    -- Timestamp de l'audit (NOW() au moment du trigger). Distinct
    -- de `updated_at` sur la row cible (qui est sur la table source).
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    -- Index composite pour les filtres courants de l'UI :
    --   WHERE agent_id = X AND action = 'update' ORDER BY id DESC
    -- L'index couvre (agent_id, action, id) pour skip-scan optimisé.
    INDEX ix_policy_audit_agent_action (agent_id, action, id),
    -- Index séparé pour le scan chronologique global (cas "all
    -- changes in the last 7 days, any agent").
    INDEX ix_policy_audit_created (created_at, id)
    -- Pas de FK vers users.id : users.id est INT(11) (pas BIGINT)
    -- donc FK avec updated_by BIGINT échoue avec errno 150. Voir
    -- PITFALL en tête de fichier. L'app fait le JOIN en SQL.
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Trigger AFTER INSERT ─────────────────────────────────────────────
-- Capture la nouvelle row dans `new_values`. `updated_by` est mis à
-- la valeur de la row insérée (qui peut être NULL pour un system seed).
-- On capture PAS de source externe (par exemple, le user via
-- `audit_user_id` session var) — voir PITFALL ci-dessous.
DROP TRIGGER IF EXISTS trg_agent_policy_audit_insert;
DELIMITER //
CREATE TRIGGER trg_agent_policy_audit_insert
AFTER INSERT ON agent_policy
FOR EACH ROW
BEGIN
    INSERT INTO policy_audit (agent_id, action, old_values, new_values, updated_by, created_at)
    VALUES (
        NEW.agent_id,
        'insert',
        NULL,                          -- pas de OLD sur un INSERT
        JSON_OBJECT(
            'id', NEW.id,
            'agent_id', NEW.agent_id,
            'metrics_bind_address', NEW.metrics_bind_address,
            'fim_watch_paths', NEW.fim_watch_paths,
            'ship_heuristic_threshold', NEW.ship_heuristic_threshold
        ),
        NEW.updated_by,
        NOW()
    );
END//
DELIMITER ;

-- ── Trigger AFTER UPDATE ─────────────────────────────────────────────
-- Capture OLD et NEW pour pouvoir faire un diff dans l'UI.
DROP TRIGGER IF EXISTS trg_agent_policy_audit_update;
DELIMITER //
CREATE TRIGGER trg_agent_policy_audit_update
AFTER UPDATE ON agent_policy
FOR EACH ROW
BEGIN
    -- Skip si aucun changement réel (les UPDATEs no-op polluent
    -- l'audit). MariaDB n'a pas de "IF" dans un trigger body avant
    -- 10.5, donc on compare les 4 champs utiles.
    IF NOT (
        OLD.metrics_bind_address <=> NEW.metrics_bind_address AND
        OLD.fim_watch_paths <=> NEW.fim_watch_paths AND
        OLD.ship_heuristic_threshold <=> NEW.ship_heuristic_threshold AND
        OLD.agent_id <=> NEW.agent_id
    ) THEN
        INSERT INTO policy_audit (agent_id, action, old_values, new_values, updated_by, created_at)
        VALUES (
            NEW.agent_id,
            'update',
            JSON_OBJECT(
                'id', OLD.id,
                'agent_id', OLD.agent_id,
                'metrics_bind_address', OLD.metrics_bind_address,
                'fim_watch_paths', OLD.fim_watch_paths,
                'ship_heuristic_threshold', OLD.ship_heuristic_threshold
            ),
            JSON_OBJECT(
                'id', NEW.id,
                'agent_id', NEW.agent_id,
                'metrics_bind_address', NEW.metrics_bind_address,
                'fim_watch_paths', NEW.fim_watch_paths,
                'ship_heuristic_threshold', NEW.ship_heuristic_threshold
            ),
            NEW.updated_by,
            NOW()
        );
    END IF;
END//
DELIMITER ;

-- ── Trigger AFTER DELETE ─────────────────────────────────────────────
-- Capture OLD uniquement. `updated_by` n'est pas accessible après
-- DELETE (NEW n'existe pas), donc on met la valeur de OLD.updated_by
-- (qui est encore lisible car OLD est défini dans un BEFORE/AFTER DELETE).
DROP TRIGGER IF EXISTS trg_agent_policy_audit_delete;
DELIMITER //
CREATE TRIGGER trg_agent_policy_audit_delete
AFTER DELETE ON agent_policy
FOR EACH ROW
BEGIN
    INSERT INTO policy_audit (agent_id, action, old_values, new_values, updated_by, created_at)
    VALUES (
        OLD.agent_id,
        'delete',
        JSON_OBJECT(
            'id', OLD.id,
            'agent_id', OLD.agent_id,
            'metrics_bind_address', OLD.metrics_bind_address,
            'fim_watch_paths', OLD.fim_watch_paths,
            'ship_heuristic_threshold', OLD.ship_heuristic_threshold
        ),
        NULL,                          -- pas de NEW sur un DELETE
        OLD.updated_by,
        NOW()
    );
END//
DELIMITER ;

-- ── Backfill : aucun (la table vient d'être créée) ──────────────────
-- Note : on NE backfill pas les anciennes mutations de agent_policy
-- (T64.1 et T64.6) car on n'a pas l'historique complet. À partir de
-- maintenant, chaque mutation est tracée.

-- ── Idempotence ──────────────────────────────────────────────────────
-- CREATE TABLE IF NOT EXISTS : idempotent
-- DROP TRIGGER IF EXISTS : idempotent
-- CREATE TRIGGER : re-crée le trigger à chaque run (avec DROP IF EXISTS avant)
-- Le migration script complet est donc re-runnable sans erreur.

-- ── PITFALL : capture de updated_by via session var ──────────────────
-- Idée initiale : utiliser `@audit_user_id` (MariaDB session var) pour
-- capturer le user SQL, et le transmettre au trigger via NEW.updated_by
-- (qui est set par l'app). Mais ça double le travail :
--   1. L'app doit déjà set `updated_by` (ce qu'elle fait, bonne pratique)
--   2. Un session var serait un autre canal qui peut diverger
-- Conclusion KISS : on se contente de NEW.updated_by (et OLD.updated_by
-- pour le DELETE). Si la mut se fait sans `updated_by` (system seed
-- ou script direct via mariadb CLI), c'est NULL et l'audit le reflète.
-- Tradeoff : on perd la trace du user pour les mutations directes
-- en SQL, mais on les trace quand même (le `agent_id` reste capturé).
