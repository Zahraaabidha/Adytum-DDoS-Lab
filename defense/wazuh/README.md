# Wazuh integration (alert correlation)

SENTINEL LAB ships Suricata's EVE JSON output (`defense/suricata/suricata.yaml`)
to a shared volume that a Wazuh manager container tails via its Suricata
decoder. Wazuh correlates:

- Suricata alerts (`alert.signature_id` in the `1000001-1000004` range defined
  in `defense/suricata/ddos.rules`)
- SENTINEL's own mitigation log (`defense/mitigation_log.jsonl`, produced by
  `defense/engine.py`) via a custom log-collector + decoder/rule pair
  (`ossec_local_rules.xml` in this directory)

This gives one place (the Wazuh dashboard) to see: raw flow/alert signals from
Suricata, cross-referenced with the ML classifier's own mitigation decisions
and the feature values that drove them.

## Wiring it up

1. Suricata writes `/var/log/suricata/eve.json` to the shared `suricata-logs`
   volume (see `docker-compose.yml`).
2. The Wazuh manager container mounts that volume read-only and its
   `ossec.conf` includes a `<localfile>` block pointing at
   `eve.json` with `<log_format>json</log_format>`.
3. `ossec_local_rules.xml` decodes SENTINEL's `mitigation_log.jsonl` the same
   way, so both signal sources land in the same Wazuh alert stream.

This is provided as a working configuration stub rather than a fully managed
Wazuh cluster, since Wazuh's own resource footprint is heavy for a learning
lab -- the manager container is optional and the rest of SENTINEL LAB
(Suricata, the classifier, dashboards) functions fully without it.
