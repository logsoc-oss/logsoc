# app/services/onboarding_service.py — Ticket #35: Onboarding auto-config logic
"""
Business rules for automatic configuration based on wizard answers.

Rules (from CDC LOGSOC-WEB Part 6 §23.1):
1. France + Énergie → frameworks: [nis2, rgpd], authority: CERT-FR, essential
2. France + Finance → frameworks: [nis2, rgpd, dora], authority: ACPR, essential
3. Allemagne (DE) → authority: BSI
4. Espagne (ES) → authority: CCN-CERT
5. <50 employés → important (allègements)
6. "Je ne sais pas" → détermination auto basée sur taille
"""
from typing import Dict, Any, List


# ── Country → authority mapping (31 European countries: 27 EU + UK + CH + NO + IS) ──
COUNTRY_AUTHORITY = {
    "FR": "ANSSI / ReCyF",
    "DE": "BSI",
    "ES": "INCIBE-CERT",
    "IT": "ACN",
    "NL": "NCSC-NL",
    "BE": "CCB",
    "LU": "ILR",
    "IE": "NCSC-IE",
    "PT": "CNCS",
    "AT": "BMI",
    "SE": "MSB",
    "DK": "CFCS",
    "FI": "Kyberturvallisuuskeskus",
    "PL": "CSIRT NASK",
    "CZ": "NUKIB",
    "SK": "SK-CERT",
    "HU": "NBSH",
    "RO": "CERT-RO",
    "BG": "CERT-BG",
    "HR": "ZSI",
    "SI": "SI-CERT",
    "EE": "RIA",
    "LV": "CERT-LV",
    "LT": "NKSC",
    "GR": "GR-CERT",
    "CY": "CSIRT-CY",
    "MT": "CSIRT-MT",
    "GB": "NCSC-UK",
    "CH": "NCSC-CH",
    "NO": "NSM",
    "IS": "CERT-IS",
}

# ── Sector → frameworks mapping (NIS2 sectors) ──
SECTOR_FRAMEWORKS = {
    "energy": ["nis2", "rgpd"],
    "finance": ["nis2", "rgpd", "dora"],
    "health": ["nis2", "rgpd"],
    "transport": ["nis2", "rgpd"],
    "digital": ["nis2", "rgpd"],
    "public": ["nis2", "rgpd"],
    "manufacturing": ["nis2", "rgpd"],
    "water": ["nis2", "rgpd"],
    "food": ["nis2", "rgpd"],
    "other": ["nis2", "rgpd"],
}

# ── Sector → default NIS2 category ──
SECTOR_DEFAULT_CATEGORY = {
    "energy": "essential",
    "finance": "essential",
    "health": "essential",
    "transport": "essential",
    "digital": "important",
    "public": "important",
    "manufacturing": "important",
    "water": "essential",
    "food": "important",
    "other": "important",
}


def determine_nis2_profile(
    country: str,
    sector: str,
    company_size: str,
    nis2_known: bool,
    nis2_category: str | None,
) -> str:
    """Determine the NIS2 profile (essential / important / unknown).

    Rules:
    - If user knows their category, use it.
    - If "Je ne sais pas" (nis2_known=False), determine auto:
        - <50 employees → important (with alleviations)
        - <250 employees → important
        - >=250 employees → based on sector default
    """
    if nis2_known and nis2_category:
        return nis2_category

    # Auto-determination based on company size
    if company_size == "<50":
        return "important"  # Alleviations apply
    elif company_size == "<250":
        return "important"
    elif company_size == ">=250":
        # Large companies: use sector default
        return SECTOR_DEFAULT_CATEGORY.get(sector.lower(), "important")
    else:
        return "important"


def generate_auto_config(
    country: str,
    sector: str,
    company_size: str,
    nis2_known: bool,
    nis2_category: str | None,
) -> Dict[str, Any]:
    """Generate the auto-config based on wizard answers.

    Returns:
        {
            "frameworks_enabled": [...],
            "authority_target": "...",
            "nis2_profile": "..."
        }
    """
    # 1. Determine NIS2 profile
    nis2_profile = determine_nis2_profile(
        country, sector, company_size, nis2_known, nis2_category
    )

    # 2. Determine authority based on country (default to ANSSI / ReCyF for unknown)
    authority = COUNTRY_AUTHORITY.get(country.upper(), "ANSSI / ReCyF")

    # 3. Determine frameworks based on sector
    sector_lower = sector.lower()
    frameworks: List[str] = SECTOR_FRAMEWORKS.get(sector_lower, ["nis2", "rgpd"])

    # 4. Sector-specific authority overrides
    if country.upper() == "FR":
        if sector_lower == "energy":
            authority = "CERT-FR"
        elif sector_lower == "finance":
            authority = "ACPR"

    # 5. Company size adjustments for <50 (alleviations)
    # Frameworks stay the same, but profile is "important" with alleviations
    # (already handled in determine_nis2_profile)

    return {
        "frameworks_enabled": frameworks,
        "authority_target": authority,
        "nis2_profile": nis2_profile,
    }