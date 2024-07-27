rule executable_au3 : info executable windows
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Match AU3 autoit executables"

	strings:
		$str_au3_01 = "AU3"
		$str_au3_02 = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D }

	condition:
		all of them
}


rule executable_pe_WinExe : info executable windows
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect PE executables"

	strings:
		$pe = "PE"

	condition:
                //MZ on the beginning of file
                uint16(0) == 0x5a4d and
		//PE at offset given by 0x3c
		($pe at (uint32(0x3c)))
}


rule WindowsExecutable
{
    meta:
        description = "Detecta arquivos executáveis do Windows (PE)"
        author = "ChatGPT"
        date = "2024-07-20"
        version = "1.0"

    strings:
        $mz = { 4D 5A }       // Assinatura "MZ" no início do arquivo
        $pe = { 50 45 00 00 } // Assinatura "PE\0\0" em offset específico

    condition:
        $mz at 0 and $pe in (0..0x200)
}


rule DotNetExecutable
{
    meta:
        description = "Detecta arquivos executáveis .NET"
        author = "ChatGPT"
        date = "2024-07-20"
        version = "1.0"

    strings:
        $mz = { 4D 5A }                        // Assinatura "MZ" no início do arquivo
        $pe = { 50 45 00 00 }                  // Assinatura "PE\0\0" em offset específico
        $dotnet = "mscoree.dll"                // Identificador do runtime .NET
        $metadata = { 42 53 4A 42 }            // Assinatura "BSJB" do metadata stream .NET

    condition:
        $mz at 0 and $pe in (0..0x200) and $dotnet and $metadata
}



rule executable_elf32 : info executable linux
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect ELF 32 bit executable"

	condition:
                //ELF magic
                uint32(0) == 0x464c457f and
		uint8(4) == 0x01
}


rule executable_elf64 : info executable linux
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect ELF 64 bit executable"

	condition:
                //ELF magic
                uint32(0) == 0x464c457f and
		uint8(4) == 0x02
}
