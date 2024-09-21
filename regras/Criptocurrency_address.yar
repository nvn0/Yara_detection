rule DetectMoneroAddress
{
    strings:
        $xmr_address = /^(4|8|9)[A-HJ-NP-Za-km-z]{93}$/
    
    condition:
        $xmr_address and filesize < 500KB
}



rule DetectBitcoinAddress
{
    strings:
        $btc_address = /^(1|3|bc1)[a-zA-Z0-9]{25,39}$/
    
    condition:
        $btc_address and filesize < 500KB
}
