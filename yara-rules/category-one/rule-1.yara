rule rule_1 {
    meta:
        description = "Demonstration rule 1."
        author = "Rem"
        reference = ""
        weight = 1
        filetype = ".txt .md"
    strings:
        $s1 = "hello" ascii wide nocase
        $s2 = "world" ascii wide nocase
    condition:
        any of them
}