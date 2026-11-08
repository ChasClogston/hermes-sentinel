# Architecture decision 001

Choose an independent companion plugin, not a direct vendor of Secret Guard. Secret Guard owns credential intake/redaction; Sentinel owns policy decisions and approvals. No raw secrets are exchanged. The prototype is not yet a Hermes plugin and cannot enforce real runtime controls until its hook adapter is verified and tested.
