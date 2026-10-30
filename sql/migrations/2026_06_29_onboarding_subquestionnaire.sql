-- Ticket #57 — Add onboarding sub-questionnaire columns
ALTER TABLE onboarding_config
  ADD COLUMN IF NOT EXISTS nis2_answer VARCHAR(20),
  ADD COLUMN IF NOT EXISTS detailed_sector VARCHAR(50),
  ADD COLUMN IF NOT EXISTS service_criticality VARCHAR(20),
  ADD COLUMN IF NOT EXISTS employee_count INT;