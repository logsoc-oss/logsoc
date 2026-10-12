# LogSOC-WEB API Reference

> Auto-extracted from FastAPI routers in `app/routers/`.
> Source of truth: `https://logsoc.anytimeadmin.info/openapi.json`
> Interactive docs: `https://logsoc.anytimeadmin.info/docs` (Swagger UI)
>                  `https://logsoc.anytimeadmin.info/redoc` (ReDoc)

Base URL: `https://logsoc.anytimeadmin.info`  
All endpoints return JSON. Auth = `Authorization: Bearer <JWT>` unless noted.

## Conventions

### Authorisation levels

| Label | Meaning |
|-------|---------|
| `public` | no JWT required — endpoint uses HMAC (agent endpoints) or is a health check |
| `user` | any authenticated user (analyst, admin, superadmin, compliance_officer) |
| `admin` | role must be `admin` or `superadmin` |
| `compliance_officer` | role must be `compliance_officer` or `admin` or `superadmin` |

### Pagination

Most list endpoints accept `skip` (offset, default 0) and `limit` (page size, default 50, max 500).

### Filtering

Common query params: `severity`, `status`, `framework`, `is_active`, `from`/`to` (ISO 8601). See per-endpoint sections.

### Errors

All errors return JSON `{"detail": "..."}`:

| Status | When |
|--------|------|
| 400 | Validation error (Pydantic) |
| 401 | Missing or invalid JWT / HMAC signature |
| 403 | Authenticated but role insufficient / agent revoked |
| 404 | Resource not found / agent ID unknown |
| 409 | Conflict (duplicate, state mismatch) |
| 500 | Server error |

---

## Endpoint index by router

| Router | Endpoints | Auth | Purpose |
|--------|-----------|------|---------|
| `actions` | 6 | admin/user | Create a pending action. If proposed_by=='agent', the agent suggested |
| `admin_llm` | 3 | admin |  |
| `agent_config` | 10 | admin/public/user | Return the current agent policy (HMAC-signed, no admin auth). |
| `agents` | 17 | public/user | Register a new agent. Creates agent in 'pending' status. |
| `ai` | 7 | admin/user | Analyze ClickHouse events and agent data to auto-generate AI insights. |
| `aiact` | 13 | admin/user | Classify an AI system based on the questionnaire (4 risk levels). |
| `alerts` | 3 | user |  |
| `assets` | 11 | admin/user | Get compliance metadata for an asset. |
| `auth` | 3 | public/user |  |
| `cases` | 12 | user | List cases, newest first, with optional filters. |
| `compliance` | 4 | user | List compliance controls with optional filters. |
| `compliance_infra` | 5 | user | Historique d'évolution d'une section (sparkline data). |
| `correlation` | 13 | admin/user | Return current correlation metrics over the configured sliding window. |
| `crisis` | 17 | admin/user | Activate a crisis from an existing case/incident. |
| `cross_mapping` | 6 | user | List all frameworks with control counts. |
| `dora` | 13 | admin/user | Classify an incident as major or not based on DORA thresholds. |
| `events` | 4 | public/user | Ingest events from an agent. Writes to ClickHouse siem_logs. |
| `frameworks_modular` | 4 | admin/user |  |
| `gdpr` | 13 | admin/compliance_officer/user | Trigger RGPD erasure for a user. |
| `gdpr_ext` | 19 | admin/user |  |
| `iso27001` | 14 | admin/user |  |
| `nis2` | 8 | admin/user |  |
| `nis2_countries` | 4 | user |  |
| `regulatory_notifications` | 9 | admin/user | Trigger parallel regulatory notifications from an incident. |
| `reporting` | 10 | admin/user | Get aggregated data for a dashboard (calls summary endpoints of other modules). |
| `risks` | 10 | admin/compliance_officer/user | List risks. Any authenticated user can read (analyst+). |
| `runbook` | 8 | admin/compliance_officer/user |  |
| `sigma` | 6 | admin/user | Top-line numbers for the /sigma dashboard tile. |
| `soar` | 14 | admin/user |  |
| `system` | 2 | public |  |
| `threat_intel` | 14 | admin/user | Lookup an IOC in the local database and return matches + correlations. |
| `users` | 6 | user |  |
| `yara` | 17 | admin/public/user | List YARA rules with optional filters. |

**Total: 305 endpoints** across 33 routers.

---

## Detailed endpoint reference

### `actions` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| POST | `/api/v1/actions/` | admin | create_action |
| GET | `/api/v1/actions/` | user | list_actions |
| GET | `/api/v1/actions/{action_id}` | admin | get_action |
| POST | `/api/v1/actions/{action_id}/approve` | admin | approve_action |
| POST | `/api/v1/actions/{action_id}/cancel` | admin | cancel_action |
| GET | `/api/v1/actions/agent/{agent_id}` | user | list_agent_actions |

---

### `admin_llm` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/admin_llm/llm/status` | admin | llm_status |
| POST | `/api/v1/admin_llm/llm/reload` | admin | llm_reload |
| GET | `/api/v1/admin_llm/llm/models` | admin | llm_models |

---

### `agent_config` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/agent_config/policy` | public | get_policy |
| PUT | `/api/v1/agent_config/policy` | admin | update_policy |
| GET | `/api/v1/agent_config/policy/agents/{agent_id}` | admin | get_agent_policy_override |
| PUT | `/api/v1/agent_config/policy/agents/{agent_id}` | admin | upsert_agent_policy_override |
| DELETE | `/api/v1/agent_config/policy/agents/{agent_id}` | admin | delete_agent_policy_override |
| GET | `/api/v1/agent_config/policy/audit` | public | get_policy_audit |
| GET | `/api/v1/agent_config/policy/audit/export` | admin | export_policy_audit_csv |
| GET | `/api/v1/agent_config/policy/audit/{audit_id}` | admin | get_policy_audit_entry |
| GET | `/api/v1/agent_config/probes` | user | get_probes |
| PUT | `/api/v1/agent_config/probes` | admin | update_probes |

---

### `agents` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| POST | `/api/v1/agents/register` | public | register_agent |
| GET | `/api/v1/agents/status` | public | get_agent_status |
| POST | `/api/v1/agents/heartbeat` | public | agent_heartbeat |
| GET | `/api/v1/agents/` | user | list_agents |
| PUT | `/api/v1/agents/{agent_id}/approve` | user | approve_agent |
| PUT | `/api/v1/agents/{agent_id}/revoke` | user | revoke_agent |
| POST | `/api/v1/agents/{agent_id}/activate` | public | activate_agent |
| PUT | `/api/v1/agents/{agent_id}/reject` | user | reject_agent |
| DELETE | `/api/v1/agents/{agent_id}` | user | delete_agent |
| POST | `/api/v1/agents/{agent_id}/rotate-wal-key` | user | rotate_wal_key |
| GET | `/api/v1/agents/{agent_id}/wal-key-status` | user | get_wal_key_status |
| POST | `/api/v1/agents/{agent_id}/hot-reload` | user | hot_reload_agent |
| POST | `/api/v1/agents/{agent_id}/action-report` | public | action_report |
| GET | `/api/v1/agents/{agent_id}/metrics` | user | get_agent_metrics |
| POST | `/api/v1/agents/{agent_id}/command` | user | post_agent_command |
| GET | `/api/v1/agents/{agent_id}/command` | user | list_agent_commands |
| POST | `/api/v1/agents/{agent_id}/command-result` | public | post_agent_command_result |

---

### `ai` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/ai/insights` | user | list_insights |
| GET | `/api/v1/ai/insights/{insight_id}` | admin | get_insight |
| POST | `/api/v1/ai/insights` | admin | create_insight |
| PUT | `/api/v1/ai/insights/{insight_id}` | admin | update_insight |
| DELETE | `/api/v1/ai/insights/{insight_id}` | admin | delete_insight |
| GET | `/api/v1/ai/insights/stats/summary` | user | insights_stats |
| POST | `/api/v1/ai/insights/analyze` | admin | analyze_patterns |

---

### `aiact` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/aiact/systems` | admin | list_systems |
| POST | `/api/v1/aiact/systems` | admin | create_system |
| GET | `/api/v1/aiact/systems/{system_id}` | admin | get_system |
| DELETE | `/api/v1/aiact/systems/{system_id}` | admin | delete_system |
| POST | `/api/v1/aiact/classify` | admin | classify_system |
| GET | `/api/v1/aiact/systems/{system_id}/obligations` | admin | get_obligations |
| PUT | `/api/v1/aiact/systems/{system_id}/obligations` | admin | update_obligations |
| GET | `/api/v1/aiact/incidents` | admin | list_incidents |
| POST | `/api/v1/aiact/incidents` | admin | create_incident |
| PUT | `/api/v1/aiact/incidents/{incident_id}` | admin | update_incident |
| GET | `/api/v1/aiact/transparency` | admin | list_transparency |
| PUT | `/api/v1/aiact/transparency/{trans_id}` | admin | update_transparency |
| GET | `/api/v1/aiact/summary` | user | aiact_summary |

---

### `alerts` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/alerts/` | user | list_alerts |
| GET | `/api/v1/alerts/summary` | user | alerts_summary |
| GET | `/api/v1/alerts/{alert_id}` | user | get_alert |

---

### `assets` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/assets/groups` | admin | list_groups |
| POST | `/api/v1/assets/groups` | admin | create_group |
| DELETE | `/api/v1/assets/groups/{group_id}` | admin | delete_group |
| GET | `/api/v1/assets/` | user | list_assets |
| GET | `/api/v1/assets/{asset_id}` | user | get_asset |
| PUT | `/api/v1/assets/{asset_id}` | admin | update_asset |
| GET | `/api/v1/assets/{asset_id}/compliance` | user | get_asset_compliance |
| PUT | `/api/v1/assets/{asset_id}/compliance` | admin | update_asset_compliance |
| GET | `/api/v1/assets/compliance/suggestions` | user | get_compliance_suggestions |
| GET | `/api/v1/assets/{asset_id}/heartbeats` | user | get_asset_heartbeats |
| GET | `/api/v1/assets/stats/summary` | user | assets_stats |

---

### `auth` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| POST | `/api/v1/auth/login` | public | login |
| POST | `/api/v1/auth/refresh` | public | refresh_token |
| POST | `/api/v1/auth/logout` | user | logout |

---

### `cases` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/cases/` | user | list_cases |
| GET | `/api/v1/cases/stats` | user | case_stats |
| POST | `/api/v1/cases/` | user | create_case |
| GET | `/api/v1/cases/{case_id}` | user | get_case |
| GET | `/api/v1/cases/by-uid/{case_uid}` | user | get_case_by_uid |
| PATCH | `/api/v1/cases/{case_id}` | user | update_case |
| POST | `/api/v1/cases/{case_id}/status` | user | change_case_status |
| POST | `/api/v1/cases/{case_id}/comments` | user | add_comment |
| GET | `/api/v1/cases/{case_id}/timeline` | user | get_timeline |
| POST | `/api/v1/cases/{case_id}/alerts` | user | link_alert |
| DELETE | `/api/v1/cases/{case_id}/alerts/{alert_id}` | user | unlink_alert |
| POST | `/api/v1/cases/{case_id}/close` | user | close_case |

---

### `compliance` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/compliance/controls` | user | list_compliance_controls |
| GET | `/api/v1/compliance/scores` | user | get_compliance_scores |
| GET | `/api/v1/compliance/controls/{control_id}` | user | get_compliance_control |
| PUT | `/api/v1/compliance/controls/{control_id}` | user | update_compliance_control |

---

### `compliance_infra` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/compliance_infra/stats` | user | get_stats |
| GET | `/api/v1/compliance_infra/section/{section_key}` | user | get_section |
| GET | `/api/v1/compliance_infra/scores` | user | list_snapshots |
| GET | `/api/v1/compliance_infra/trend/{section_key}` | user | get_trend |
| POST | `/api/v1/compliance_infra/snapshot` | user | persist_snapshot |

---

### `correlation` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/correlation/stats` | admin | stats |
| GET | `/api/v1/correlation/config` | admin | get_threshold_config |
| PUT | `/api/v1/correlation/config` | admin | update_threshold_config |
| POST | `/api/v1/correlation/config/reset` | admin | reset_threshold_config |
| POST | `/api/v1/correlation/scan` | admin | trigger_scan |
| GET | `/api/v1/correlation/rules` | user | list_rules |
| GET | `/api/v1/correlation/alerts` | user | list_correlation_alerts |
| GET | `/api/v1/correlation/mitre/rules` | user | list_mitre_rules |
| PATCH | `/api/v1/correlation/mitre/rules/{rule_id}` | admin | toggle_mitre_rule |
| GET | `/api/v1/correlation/mitre/coverage` | user | mitre_coverage |
| GET | `/api/v1/correlation/mitre/navigator` | user | mitre_navigator |
| GET | `/api/v1/correlation/mitre/alerts` | user | list_mitre_alerts |
| GET | `/api/v1/correlation/ebpf-enriched` | user | ebpf_enriched |

---

### `crisis` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/crisis/playbooks` | user | list_playbooks |
| GET | `/api/v1/crisis/playbooks/{scenario}` | admin | get_playbook |
| POST | `/api/v1/crisis/activate` | admin | activate_crisis |
| GET | `/api/v1/crisis/` | user | list_crises |
| GET | `/api/v1/crisis/{crisis_id}` | user | get_crisis |
| PUT | `/api/v1/crisis/{crisis_id}/status` | admin | update_crisis_status |
| POST | `/api/v1/crisis/{crisis_id}/cell` | admin | add_cell_member |
| GET | `/api/v1/crisis/{crisis_id}/cell` | admin | get_cell_members |
| DELETE | `/api/v1/crisis/{crisis_id}/cell/{member_id}` | admin | remove_cell_member |
| POST | `/api/v1/crisis/{crisis_id}/actions` | admin | create_action |
| GET | `/api/v1/crisis/{crisis_id}/actions` | admin | get_actions |
| PUT | `/api/v1/crisis/{crisis_id}/actions/{action_id}` | admin | update_action |
| POST | `/api/v1/crisis/{crisis_id}/communications` | admin | create_communication |
| GET | `/api/v1/crisis/{crisis_id}/communications` | admin | get_communications |
| PUT | `/api/v1/crisis/{crisis_id}/communications/{comm_id}` | admin | update_communication |
| POST | `/api/v1/crisis/{crisis_id}/postmortem` | admin | create_postmortem |
| GET | `/api/v1/crisis/{crisis_id}/postmortem` | user | get_postmortem |

---

### `cross_mapping` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/cross_mapping/frameworks` | user | list_frameworks |
| GET | `/api/v1/cross_mapping/controls` | user | list_controls |
| GET | `/api/v1/cross_mapping/cross` | user | get_cross_mapping |
| GET | `/api/v1/cross_mapping/{fw1}/{fw2}` | user | get_framework_pair_mapping |
| GET | `/api/v1/cross_mapping/unified-dashboard` | user | unified_dashboard |
| GET | `/api/v1/cross_mapping/summary` | user | mapping_summary |

---

### `dora` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/dora/pillars` | admin | list_pillars |
| PUT | `/api/v1/dora/pillars/{pillar}` | admin | update_pillar |
| POST | `/api/v1/dora/incidents` | admin | classify_incident |
| GET | `/api/v1/dora/incidents` | user | list_incidents |
| GET | `/api/v1/dora/incidents/{incident_id}` | user | get_incident |
| GET | `/api/v1/dora/third-parties` | admin | list_third_parties |
| POST | `/api/v1/dora/third-parties` | admin | create_third_party |
| PUT | `/api/v1/dora/third-parties/{tp_id}` | admin | update_third_party |
| DELETE | `/api/v1/dora/third-parties/{tp_id}` | admin | delete_third_party |
| GET | `/api/v1/dora/resilience-tests` | admin | list_tests |
| POST | `/api/v1/dora/resilience-tests` | admin | create_test |
| PUT | `/api/v1/dora/resilience-tests/{test_id}` | admin | update_test |
| GET | `/api/v1/dora/summary` | user | dora_summary |

---

### `events` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| POST | `/api/v1/events/` | public | ingest_events |
| GET | `/api/v1/events/` | user | list_events |
| GET | `/api/v1/events/stats/summary` | user | events_stats |
| GET | `/api/v1/events/{event_id}` | user | get_event |

---

### `frameworks_modular` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/frameworks_modular/` | user | list_frameworks |
| GET | `/api/v1/frameworks_modular/summary` | user | frameworks_summary |
| GET | `/api/v1/frameworks_modular/{framework}` | user | get_framework_assessment |
| PUT | `/api/v1/frameworks_modular/{framework}/{control_id}` | admin | update_assessment |

---

### `gdpr` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| POST | `/api/v1/gdpr/gdpr/erasure` | compliance_officer | post_gdpr_erasure |
| GET | `/api/v1/gdpr/gdpr/audit` | user | list_gdpr_audit |
| GET | `/api/v1/gdpr/gdpr/audit/export` | user | export_gdpr_audit |
| GET | `/api/v1/gdpr/gdpr/audit/{erasure_ref}` | user | get_gdpr_audit |
| GET | `/api/v1/gdpr/retention/policies` | user | list_retention_policies |
| GET | `/api/v1/gdpr/retention/policies/{data_domain}` | user | get_retention_policy |
| PUT | `/api/v1/gdpr/retention/policies/{data_domain}` | admin | update_retention_policy |
| POST | `/api/v1/gdpr/retention/refresh` | admin | post_retention_refresh |
| GET | `/api/v1/gdpr/retention/registry/stats` | user | get_retention_registry_stats |
| POST | `/api/v1/gdpr/retention/archive/sweep` | admin | post_archive_sweep |
| GET | `/api/v1/gdpr/retention/archive/manifests/{data_domain}` | user | list_pending_manifests |
| POST | `/api/v1/gdpr/retention/archive/{data_domain}/confirm` | admin | post_archive_confirm |
| GET | `/api/v1/gdpr/retention/restore` | user | get_retention_restore |

---

### `gdpr_ext` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/gdpr_ext/treatments` | admin | list_treatments |
| POST | `/api/v1/gdpr_ext/treatments` | admin | create_treatment |
| GET | `/api/v1/gdpr_ext/treatments/{treatment_id}` | admin | get_treatment |
| DELETE | `/api/v1/gdpr_ext/treatments/{treatment_id}` | admin | delete_treatment |
| GET | `/api/v1/gdpr_ext/dpia` | admin | list_dpia |
| POST | `/api/v1/gdpr_ext/dpia` | admin | create_dpia |
| PUT | `/api/v1/gdpr_ext/dpia/{dpia_id}/approve` | admin | approve_dpia |
| GET | `/api/v1/gdpr_ext/requests` | admin | list_requests |
| POST | `/api/v1/gdpr_ext/requests` | admin | create_request |
| PUT | `/api/v1/gdpr_ext/requests/{request_id}` | admin | update_request |
| GET | `/api/v1/gdpr_ext/subprocessors` | admin | list_subprocessors |
| POST | `/api/v1/gdpr_ext/subprocessors` | admin | create_subprocessor |
| DELETE | `/api/v1/gdpr_ext/subprocessors/{sub_id}` | admin | delete_subprocessor |
| GET | `/api/v1/gdpr_ext/transfers` | admin | list_transfers |
| POST | `/api/v1/gdpr_ext/transfers` | admin | create_transfer |
| GET | `/api/v1/gdpr_ext/breaches` | admin | list_breaches |
| POST | `/api/v1/gdpr_ext/breaches` | admin | create_breach |
| PUT | `/api/v1/gdpr_ext/breaches/{breach_id}` | admin | update_breach |
| GET | `/api/v1/gdpr_ext/summary` | user | gdpr_summary |

---

### `iso27001` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/iso27001/soa` | user | list_soa |
| GET | `/api/v1/iso27001/soa/{control_id}` | admin | get_soa_control |
| PUT | `/api/v1/iso27001/soa/{control_id}` | admin | update_soa_control |
| GET | `/api/v1/iso27001/audits` | admin | list_audits |
| POST | `/api/v1/iso27001/audits` | admin | create_audit |
| PUT | `/api/v1/iso27001/audits/{audit_id}` | admin | update_audit |
| GET | `/api/v1/iso27001/nonconformities` | admin | list_ncs |
| POST | `/api/v1/iso27001/nonconformities` | admin | create_nc |
| PUT | `/api/v1/iso27001/nonconformities/{nc_id}` | admin | update_nc |
| GET | `/api/v1/iso27001/management-reviews` | admin | list_reviews |
| POST | `/api/v1/iso27001/management-reviews` | admin | create_review |
| GET | `/api/v1/iso27001/certification` | admin | list_certifications |
| POST | `/api/v1/iso27001/certification` | admin | create_certification |
| GET | `/api/v1/iso27001/summary` | user | iso27001_summary |

---

### `nis2` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/nis2/classification` | admin | get_classification |
| PUT | `/api/v1/nis2/classification` | admin | update_classification |
| GET | `/api/v1/nis2/measures` | user | list_measures |
| GET | `/api/v1/nis2/measures/{measure_code}` | user | get_measure |
| PUT | `/api/v1/nis2/measures/{measure_id}/assessment` | admin | update_assessment |
| GET | `/api/v1/nis2/governance` | admin | list_governance |
| POST | `/api/v1/nis2/governance` | admin | create_governance |
| GET | `/api/v1/nis2/summary` | user | nis2_summary |

---

### `nis2_countries` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/nis2_countries/countries` | user | list_countries |
| GET | `/api/v1/nis2_countries/countries/{country_code}` | user | get_country |
| GET | `/api/v1/nis2_countries/countries/{country_code}/authority` | user | get_authority |
| GET | `/api/v1/nis2_countries/summary` | user | countries_summary |

---

### `regulatory_notifications` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| POST | `/api/v1/regulatory_notifications/trigger` | admin | trigger_notifications |
| GET | `/api/v1/regulatory_notifications/` | user | list_notifications |
| GET | `/api/v1/regulatory_notifications/{notif_id}` | user | get_notification |
| PUT | `/api/v1/regulatory_notifications/{notif_id}` | admin | update_notification |
| GET | `/api/v1/regulatory_notifications/templates/{regulation}` | admin | get_templates |
| POST | `/api/v1/regulatory_notifications/{notif_id}/render` | admin | render_notification |
| GET | `/api/v1/regulatory_notifications/timers/pending` | admin | get_pending_timers |
| POST | `/api/v1/regulatory_notifications/timers/{timer_id}/ack` | admin | ack_timer |
| GET | `/api/v1/regulatory_notifications/summary` | user | notifications_summary |

---

### `reporting` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/reporting/dashboards` | user | list_dashboards |
| GET | `/api/v1/reporting/dashboards/{dashboard_type}` | user | get_dashboard |
| GET | `/api/v1/reporting/dashboards/{dashboard_type}/data` | user | get_dashboard_data |
| GET | `/api/v1/reporting/templates` | admin | list_templates |
| POST | `/api/v1/reporting/generate` | admin | generate_report |
| GET | `/api/v1/reporting/schedules` | admin | list_schedules |
| POST | `/api/v1/reporting/schedules` | admin | create_schedule |
| DELETE | `/api/v1/reporting/schedules/{schedule_id}` | admin | delete_schedule |
| GET | `/api/v1/reporting/history` | user | list_history |
| GET | `/api/v1/reporting/summary` | user | reporting_summary |

---

### `risks` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/risks/` | user | list_risks |
| GET | `/api/v1/risks/stats` | user | get_risk_stats |
| GET | `/api/v1/risks/{risk_id}` | compliance_officer | get_risk |
| POST | `/api/v1/risks/` | compliance_officer | create_risk |
| PATCH | `/api/v1/risks/{risk_id}` | compliance_officer | update_risk |
| DELETE | `/api/v1/risks/{risk_id}` | admin | delete_risk |
| POST | `/api/v1/risks/{risk_id}/ai-suggest` | compliance_officer | create_ai_suggestion |
| GET | `/api/v1/risks/{risk_id}/ai-suggestions` | user | list_ai_suggestions |
| POST | `/api/v1/risks/{risk_id}/ai-suggestions/{suggestion_id}/apply` | compliance_officer | apply_ai_suggestion |
| POST | `/api/v1/risks/{risk_id}/ai-suggest-llm` | compliance_officer | create_ai_suggestion_llm |

---

### `runbook` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/runbook/` | user | list_procedures |
| GET | `/api/v1/runbook/stats` | user | get_stats |
| GET | `/api/v1/runbook/{procedure_id}` | compliance_officer | get_procedure |
| POST | `/api/v1/runbook/` | compliance_officer | create_procedure |
| PUT | `/api/v1/runbook/{procedure_id}` | compliance_officer | update_procedure |
| DELETE | `/api/v1/runbook/{procedure_id}` | admin | delete_procedure |
| POST | `/api/v1/runbook/{procedure_id}/reviews` | compliance_officer | add_review |
| GET | `/api/v1/runbook/{procedure_id}/reviews` | user | list_reviews |

---

### `sigma` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/sigma/stats` | user | sigma_stats |
| GET | `/api/v1/sigma/` | user | list_sigma_rules |
| GET | `/api/v1/sigma/{uuid}` | user | get_sigma_rule |
| PATCH | `/api/v1/sigma/{uuid}` | user | update_sigma_rule |
| POST | `/api/v1/sigma/import` | admin | sigma_import |
| POST | `/api/v1/sigma/evaluate` | admin | sigma_evaluate |

---

### `soar` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/soar/playbooks` | admin | list_playbooks |
| POST | `/api/v1/soar/playbooks` | admin | create_playbook |
| GET | `/api/v1/soar/playbooks/{playbook_id}` | admin | get_playbook |
| PUT | `/api/v1/soar/playbooks/{playbook_id}` | admin | update_playbook |
| DELETE | `/api/v1/soar/playbooks/{playbook_id}` | admin | delete_playbook |
| POST | `/api/v1/soar/execute` | admin | execute_playbook |
| GET | `/api/v1/soar/executions` | user | list_executions |
| GET | `/api/v1/soar/executions/{exec_id}` | user | get_execution |
| GET | `/api/v1/soar/approvals/pending` | admin | list_pending_approvals |
| POST | `/api/v1/soar/approvals/{approval_id}` | admin | decide_approval |
| GET | `/api/v1/soar/integrations` | admin | list_integrations |
| POST | `/api/v1/soar/integrations` | admin | create_integration |
| PUT | `/api/v1/soar/integrations/{integ_id}/test` | admin | test_integration |
| GET | `/api/v1/soar/summary` | user | soar_summary |

---

### `system` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/system/health` | public | health |
| GET | `/api/v1/system/health/details` | public | health_details |

---

### `threat_intel` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/threat_intel/indicators` | user | list_indicators |
| POST | `/api/v1/threat_intel/indicators` | admin | create_indicator |
| DELETE | `/api/v1/threat_intel/indicators/{indicator_id}` | admin | delete_indicator |
| POST | `/api/v1/threat_intel/lookup` | admin | lookup_ioc |
| GET | `/api/v1/threat_intel/actors` | admin | list_actors |
| POST | `/api/v1/threat_intel/actors` | admin | create_actor |
| GET | `/api/v1/threat_intel/feeds` | admin | list_feeds |
| POST | `/api/v1/threat_intel/feeds` | admin | create_feed |
| POST | `/api/v1/threat_intel/feeds/{feed_id}/sync` | admin | sync_feed |
| GET | `/api/v1/threat_intel/bulletins` | admin | list_bulletins |
| POST | `/api/v1/threat_intel/bulletins` | admin | create_bulletin |
| PUT | `/api/v1/threat_intel/bulletins/{bulletin_id}/publish` | admin | publish_bulletin |
| GET | `/api/v1/threat_intel/correlations` | user | list_correlations |
| GET | `/api/v1/threat_intel/summary` | user | ti_summary |

---

### `users` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/users/` | user | list_users |
| GET | `/api/v1/users/me` | user | get_me |
| GET | `/api/v1/users/{user_id}` | user | get_user |
| POST | `/api/v1/users/` | user | create_user |
| PUT | `/api/v1/users/{user_id}` | user | update_user |
| DELETE | `/api/v1/users/{user_id}` | user | delete_user |

---

### `yara` router

| Method | Path | Auth | Function |
|--------|------|------|----------|
| GET | `/api/v1/yara/rules` | user | list_yara_rules |
| POST | `/api/v1/yara/rules` | admin | create_yara_rule |
| GET | `/api/v1/yara/active` | public | get_active_yara_rules |
| POST | `/api/v1/yara/results` | public | post_yara_result |
| GET | `/api/v1/yara/results` | user | list_yara_results |
| GET | `/api/v1/yara/stats` | user | yara_stats |
| POST | `/api/v1/yara/import-sigbase` | admin | import_sigbase |
| GET | `/api/v1/yara/rules/{rule_id}` | admin | get_yara_rule |
| PUT | `/api/v1/yara/rules/{rule_id}` | admin | update_yara_rule |
| DELETE | `/api/v1/yara/rules/{rule_id}` | admin | delete_yara_rule |
| POST | `/api/v1/yara/rules/{rule_id}/toggle` | admin | toggle_yara_rule |
| POST | `/api/v1/yara/scan` | public | scan_content |
| GET | `/api/v1/yara/agent-stats/{agent_id}` | user | get_agent_stats |
| POST | `/api/v1/yara/reload` | admin | reload_yara_scanner |
| GET | `/api/v1/yara/ruleset` | public | get_yara_ruleset_metadata |
| GET | `/api/v1/yara/ruleset/download` | public | download_yara_ruleset |
| PUT | `/api/v1/yara/ruleset` | admin | put_yara_ruleset |

---

## Cross-cutting

### WebSocket

`/api/v1/ws/events` — push channel for live events (React dashboard). Auth via JWT query param: `?token=<jwt>`.

### HMAC-signed agent endpoints

The following endpoints use HMAC-SHA256 authentication (NOT JWT):

| Endpoint | Headers |
|----------|---------|
| `POST /api/v1/events/` | `X-Agent-Id`, `X-Timestamp`, `X-Signature` (+ `X-Nonce` if T14.1 opt-in) |
| `POST /api/v1/agents/heartbeat` | `X-Agent-Id`, `X-Timestamp`, `X-Signature` |
| `POST /api/v1/agents/register` | (no HMAC — public enrollment) |
| `GET /api/v1/agents/status` | (no HMAC — activation polling) |
| `GET /api/v1/yara/active` | HMAC (agent ruleset pull) |
| `POST /api/v1/yara/results` | HMAC (agent match upload) |
| `POST /api/v1/yara/scan` | HMAC (agent file upload) |
| `GET /api/v1/yara/ruleset` | HMAC (agent ruleset pull) |
| `GET /api/v1/yara/ruleset/download` | HMAC (agent ruleset download) |

HMAC signature calculation:
```
canonical_payload = <X-Timestamp> + "." + <X-Nonce-or-empty> + "." + <body_sha256_hex>
X-Signature = HMAC_SHA256(key=hmac_key, message=canonical_payload).hex()
```

### ClickHouse event schema (siem_logs)

The agent sends events with these fields, all stored in ClickHouse:

| Field | Type | Source |
|-------|------|--------|
| `received_at` | DateTime64 | Backend timestamp |
| `agent_id` | String | X-Agent-Id header |
| `source_host` | String | Agent hostname |
| `source_ip` | String | Agent IP |
| `severity` | UInt8 | Agent severity_map / eBPF scorer |
| `event` | String | Event type (execve, open, fim, etc.) |
| `message` | String | Human-readable message |
| `raw_message` | String | Original message |
| `raw_event` | String | Original JSON from collector (T14.6) |
| `truncated` | UInt8 | Message truncated flag (T14.6) |
| `orig_len` | UInt32 | Original message length (T14.6) |
| `comm` | String | Process command |
| `pid` | UInt32 | Process ID |
| `uid` | UInt32 | User ID |
| `severity_score` | Int32 | eBPF severity score (T14.4) |
| `mitre` | Array(String) | MITRE ATT&CK techniques (T14.4) |
| `sigma` | String | Sigma matches (JSON-serialized, T14.5) |
| `argv` | String | Execve command line (T14.4) |
| `action` | String | FIM action (create/modify/delete) |
| `sha256` | String | File hash (FIM) |
| `count` | UInt16 | Coalesced event count (T14.0b) |
| `pids` | Array(UInt32) | Coalesced PIDs (T14.0b) |
| `ebpf_match` | UInt8 | eBPF↔journald cross-validation |
| `correlation_window_ms` | Int64 | Correlation window |

### Agent identity and hostname tracking (T14.6)

The `agents` table tracks hostname renames:
- `agent_id` (UUID) = stable primary key
- `hostname` = current hostname (updated on each heartbeat)
- `source_host_history` = JSON array of previous hostnames
- `hostname_updated_at` = timestamp of last rename

See `doc/developer-backend.md` (SOC-AGENT repo) § 7 for the full spec.

### Rate limiting

No rate limiting as of v0.7.x. Tracked for a future release (nginx `limit_req`).

### CORS

CORS allows the dashboard origin only (`https://logsoc.anytimeadmin.info`). Agent endpoints are server-to-server.

### Times

All timestamps stored in UTC. API returns ISO 8601 strings.

---

## Compliance Modules — Full Reference

### September session — Gouvernance (rétro-ajouté, voir openapi.json pour le détail)

| Router | Prefix | Endpoints clés | Garde |
|--------|--------|----------------|-------|
| `practices` | `/api/v1/grc` | pratiques (liste+facettes, cockpit, prepare-audit par SÉLECTION d'exigences, audit-pending/history, cahier figé, constats, rapports signés pyHanko, déclaration terrain practice×asset) | require_permission (read/write/delete) + scoping service |
| `business_questionnaires` | `/api/v1/business-questionnaires` | questionnaires service×type (rgpd_processing=DPO, essential_activities=RSSI), envoi/réponses/clôture | domaine DPO/RSSI + scoping membres |
| `business_roles` | `/api/v1/business-roles` | référentiel casquettes métier (CRUD, seed verrouillées, soft-delete) | admin |
| `service_members` | `/api/v1/services` | appartenance users↔services (membres, is_owner) | admin / rôles forts |
| `settings_practices` | `/api/v1/settings` | fréquence d'audit par défaut (GET lit le DISQUE — uvicorn multi-workers, jamais cfg_get) | admin |
| `roles/permissions` | `/api/v1/admin` | matrice 8 rôles × 15 modules × 4 actions, module_flags (off=503 sauf superadmin) | superadmin |

PITFALLs documentés : attribut permission `can_read` (pas `read`) ; GET settings multi-worker = lecture disque (`yaml.safe_load` direct).

For detailed compliance API (NIS2, DORA, RGPD, ISO 27001, AI Act, SOAR, Threat Intel, Reporting, Cross-mapping), see **[COMPLIANCE_API.md](COMPLIANCE_API.md)**.

Modules (T85-T97):
- `nis2` — 8 endpoints
- `dora` — 13 endpoints
- `gdpr_ext` — 19 endpoints
- `iso27001` — 14 endpoints
- `aiact` — 13 endpoints
- `soar` — 14 endpoints
- `threat_intel` — 14 endpoints
- `reporting` — 10 endpoints
- `cross_mapping` — 6 endpoints
- `nis2_countries` — 4 endpoints
- `frameworks_modular` — 4 endpoints
- `regulatory_notifications` — 9 endpoints
- `crisis` — 17 endpoints

_Total: 305 endpoints across 33 routers._
_Last updated: 2026-06-19_
