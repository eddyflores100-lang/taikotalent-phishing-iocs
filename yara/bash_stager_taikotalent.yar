rule Bash_Stager_Taikotalent_Oct2026 {
    meta:
        author = "Edison Flores (AliceLabs)"
        date = "2026-10-09"
        description = "deepfake_guard bash stager served from taikotalent.xyz/verify_m"
        reference = "https://github.com/eddyflores100-lang/taikotalent-phishing-iocs"
        sample_sha256 = "c7c22e322c17bda8198257342d4034af6250a5c433242461b870879ba9aa285d"
    strings:
        $c2a    = "api.gaganata.ink" ascii
        $c2b    = "api.fallgganata.ink" ascii
        $stage  = ".kdm." ascii
        $name   = "deepfake_guard" ascii
        $beacon = "guard-launcher-result" ascii
        $relax  = "nohup" ascii
    condition:
        filesize >= 40000 and filesize <= 60000 and 3 of ($c2a, $c2b, $stage, $name, $beacon, $relax)
}
