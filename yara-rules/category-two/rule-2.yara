rule rule_2 {
    meta:
        description = "Demonstration rule 1."
        author = "Rem"
        reference = ""
        weight = 1
        filetype = ".py .pyc"
    strings:
        $s1 = "foo" ascii wide nocase
        $s2 = "bar" ascii wide nocase
        $s3 = "baz" ascii wide nocase
    condition:
        any of them
}