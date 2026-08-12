# 12-Aug false-positive matrix

- architecture detection alone → clean
- ordinary architecture-aware installer → clean
- disabled install hooks alone → not safe proof, but no suspicious verdict without dependency evidence
- LaunchAgent registration alone → clean
- legitimate install/update persistence → clean
- temporary first-stage removal with no persistent effect → remediation resolved
- symbol alone → static hint, not runtime observation
- secondary severity amplification without corroboration → not canonical impact
- newly ingested older report → not threat-new
