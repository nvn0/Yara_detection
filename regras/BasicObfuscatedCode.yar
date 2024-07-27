rule BasicObfuscatedCode
{
    meta:
        description = "Detecta arquivos com possíveis ofuscações no código, pode gerar falsos positivos"
        author = "ChatGPT"
        date = "2024-07-20"
        version = "1.0"

    strings:
        $long_string = /[A-Za-z0-9+\/=]{100,}/     // Sequências longas de caracteres base64
        $unicode_gibberish = /[\x00-\x1F\x7F-\xFF]{8,}/   // Sequências longas de caracteres de controle ou não ASCII
        $packed_code = /[A-Fa-f0-9]{50,}/       // Sequências longas de caracteres hexadecimais
        $suspicious_function = "eval("            // Uso de eval (em JavaScript, por exemplo)
        $suspicious_function2 = "FromBase64String" // Função de decodificação Base64 em .NET

    condition:
        2 of ($long_string, $unicode_gibberish, $packed_code, $suspicious_function, $suspicious_function2)
}
