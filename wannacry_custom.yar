rule WannaCry_Custom_Detector
{
    meta:
        author          = "Shira Borochovich"
        description     = "Detects WannaCry ransomware using unique string and structural traits"
        date            = "2025-01-20"
        version         = "1.0"
        malware_family  = "WannaCry"
        sample_note     = "Tested on sample from theZoo ransomware collection"
        reference       = "https://github.com/ShiraBorochovich/wannacry-detector"

    tags = ["ransomware", "wannacry", "tor", "yara", "encryption", "mutex"]

    strings:
        $mz = { 4D 5A }                         // MZ Header
        $wncry_ext = ".WNCRY"                  // File extension appended by WannaCry
        $tor1 = "tor2web" ascii                // Communication via TOR2WEB (seen in some variants)
        $svcname = "mssecsvc2.0" ascii         // Name of WannaCry’s service
        $mutex = "Global\\MsWinZonesCacheCounterMutexA" ascii // Unique mutex
        $dropper = "@WanaDecryptor@" ascii     // GUI component dropped by WannaCry
        $lang = "msg/m_bulgarian.wnry" ascii   // Specific language file used

    condition:
        uint16(0) == 0x5A4D and
        all of ($wncry_ext, $svcname, $dropper, $mutex) and
        any of ($tor1, $lang)
}
