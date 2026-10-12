-- Migration 2026-09-13i: questionnaires de validation Directions Métiers
-- Le service répond (RGPD: inventaire traitements / Homologation: activités
-- essentielles). Créé par DPO (rgpd) ou RSSI (homologation), clôturé par
-- le créateur du domaine (décision Fabrice: chacun son domaine).
CREATE TABLE IF NOT EXISTS business_questionnaires (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_id INT NOT NULL,
    qtype VARCHAR(32) NOT NULL,          -- rgpd_processing | essential_activities
    title VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'brouillon',  -- brouillon|envoye|repondu|valide
    created_by INT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    sent_at DATETIME NULL,
    responded_at DATETIME NULL,
    validated_at DATETIME NULL,
    validated_by INT NULL,
    UNIQUE KEY uq_service_qtype (service_id, qtype),
    INDEX idx_bq_service (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS questionnaire_questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    questionnaire_id INT NOT NULL,
    position INT NOT NULL DEFAULT 0,
    text TEXT NOT NULL,
    qtype VARCHAR(32) NOT NULL DEFAULT 'texte',  -- texte | choix | booleen
    options TEXT NULL,                          -- JSON (choix)
    prefill TEXT NULL,                           -- pré-remplissage IA
    required TINYINT(1) NOT NULL DEFAULT 1,
    INDEX idx_qq_quest (questionnaire_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS questionnaire_answers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question_id INT NOT NULL,
    questionnaire_id INT NOT NULL,
    answer TEXT NULL,
    answered_by INT NULL,
    answered_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_qa_quest (questionnaire_id),
    UNIQUE KEY uq_qa_question (question_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;