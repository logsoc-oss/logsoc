#!/bin/bash
# LogSOC: installation des seeds de reference (gouvernance sans IA)
# Usage: bash scripts/install_seed.sh [database] (defaut: logsoc)
DB=${1:-logsoc}
cd $(dirname $0)/../sql/seeds
for f in 00_reference_documents.sql 02_governance_deliverables.sql 01_reference_requirements.sql 03_capability_dictionary.sql 04_target_resolutions.sql 05_security_practices.sql 06_business_roles.sql; do
  echo "== $f"
  mysql -u root $DB < $f || { echo ECHEC sur $f; exit 1; }
done
echo OK — seeds charges