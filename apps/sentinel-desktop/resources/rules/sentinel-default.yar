rule AIOM_Benign_Marker : synthetic installation_check {
    meta:
        author = "AIOM Sentinel"
        severity = "LOW"
        purpose = "benign deterministic integration fixture"
    strings:
        $marker = "HARMLESS_SENTINEL_YARA_X_MARKER"
    condition:
        $marker
}
