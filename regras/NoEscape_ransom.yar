
/*
rule MYG_RALWARE_d12565cc77664a5a391b7453e8e18dffc2487c3bc5291662a8d3f406287B9498_tmp {
    meta:
        author = "Malcore Yara Generator"
        ref = "https://malcore.io"
        copyright = "Internet 2. e Pty Ltd"
        file_sha256 = "68ff9855262b7a9c27e349c5e3bf68b2fc9f9ca32a9d2b844f2265dccd2bc0d8"

    strings:
        // specific strings found in binary
        $specific1 = "CryptDestroyKey"
        $specific2 = "CryptReleaseContext"
        $specific3 = "CryptStringToBinaryA"
        $specific4 = "CryptSetKeyParam"

        // hex strings found in binary
        $hex_string1 = { 75 f8 89 45 fc 89 03 89 7b e8 3f b5 81 ee 8b 45 fc 83 }
        $hex_string2 = { 7a 46 34 6b 77 55 46 7B 36 51 64 49 6c 46 49 6b 35 34 6e }
        $hex_string3 = { 2b 59 ea 7f 17 15 7a 53 b9 37 24 d4 54 67 28 fa 98 8b db c2 }
        $hex_string4 = { ee ee 72 18 8b fc 83 23 2b c2 83 ce fc 83 f8 77 }

        // matchable strings in the binary
        $match_string1 = ""
        $match_string2 = ""
        $match_string3 = ""
        $match_string4 = ""

    condition:
        2 of ($specific*) and 2 of ($hex_string*) and 1 of ($match_string*) and uint16(0) == 0x4d5a
}
*/