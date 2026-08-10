rule AIOM_Benign_Marker : synthetic installation_check {
    meta:
        author = "AIOM Sentinel"
        severity = "LOW"
    strings:
        $marker = "HARMLESS_SENTINEL_YARA_X_MARKER"
    condition:
        $marker
}
