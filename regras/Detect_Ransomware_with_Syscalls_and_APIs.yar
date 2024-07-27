rule Detect_Ransomware_with_Syscalls_and_APIs
{
    meta:
        description = "Regra para detectar características comuns de ransomware, incluindo chamadas de sistema para acesso a pastas e APIs de manipulação de processos"
        author = "ChatGPT"
        date = "2024-07-22"
        version = "1.2"
    
    strings:
        // Strings comuns encontradas em ransomwares conhecidos
        $string1 = "Your files have been encrypted" nocase
        $string2 = "decrypt your files" nocase
        $string3 = "Bitcoin address" nocase
        $string4 = "ransom note" nocase
        $string5 = "Decryptor" nocase
        $string6 = { 89 6c 70 6d 43 72 65 61 74 65 46 69 6c 65 00 }
        $string7 = { 70 61 79 6c 6f 61 64 00 }

        // Chamadas de sistema comuns relacionadas ao acesso a pastas
        $syscall1 = "NtCreateFile"
        $syscall2 = "NtOpenFile"
        $syscall3 = "NtReadFile"
        $syscall4 = "NtWriteFile"
        $syscall5 = "NtDeleteFile"
        $syscall6 = "NtSetInformationFile"
        $syscall7 = "NtQueryDirectoryFile"
        $syscall8 = "CreateFileW"
        $syscall9 = "MoveFileW"
        $syscall10 = "DeleteFileW"
        
        // Chamadas de API comuns para manipulação de processos
        $api1 = "ReadProcessMemory"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAllocEx"
        $api4 = "CreateRemoteThread"
        $api5 = "OpenProcess"
        $api6 = "GetModuleHandle"
        $api7 = "GetProcAddress"
        $api8 = "LoadLibrary"
        $api9 = "VirtualProtectEx"
        $api10 = "TerminateProcess"
    
    condition:
        // A condição para detecção: presença de qualquer uma das strings, syscalls ou APIs definidas
        any of ($string*) and any of ($syscall*) and any of ($api*)
}
