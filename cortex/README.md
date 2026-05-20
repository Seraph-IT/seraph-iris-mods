# cortex/

Custom analyzers and responders for Cortex.

## V1 Status

**Empty for V1.** Cortex is consumed via standard upstream analyzers
(VirusTotal_GetReport, MISP_2_1, AbuseIPDB, Hybrid_Analysis, URLScan_io,
HIBP_Query) without modifications.

## Phase-2 Roadmap

- Custom Responders for auto-block actions (firewall, EDR isolation, IAM disable)
- Custom Analyzer for AbuseIPDB-Pro tier (commercial)
- Custom Analyzer for internal threat-intel datasets

When Phase-2 ships, modules will be added here as subdirectories with
individual READMEs, following the same pattern as `iris/` and `misp/`.
