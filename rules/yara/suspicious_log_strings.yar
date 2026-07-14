rule Suspicious_BruteForce_Tooling_Strings
{
    meta:
        description = "Flags log entries mentioning common brute-force / credential-stuffing tool names"
        author = "SOC Analyzer"
        reference = "internal"

    strings:
        $tool1 = "hydra" nocase
        $tool2 = "medusa" nocase
        $tool3 = "ncrack" nocase
        $tool4 = "crowbar" nocase
        $tool5 = "patator" nocase

    condition:
        any of them
}

rule Suspicious_Root_Or_Admin_Bruteforce_Target
{
    meta:
        description = "Flags repeated failed logins targeting root/admin accounts, common brute-force targets"
        author = "SOC Analyzer"

    strings:
        $fail_root = "Failed password for root" nocase
        $fail_admin = "Failed password for admin" nocase
        $fail_invalid = "Failed password for invalid user" nocase

    condition:
        any of them
}
