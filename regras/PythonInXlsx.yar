rule DetectPythonCodeInXlsx
{
    meta:
        description = "Detecta a presença de código Python em arquivos .xlsx"
        author = "ChatGPT"
        date = "2024-07-20"
        version = "1.0"

    strings:
        $xlsx_header = { 50 4B 03 04 }                // Assinatura de arquivo ZIP
        $workbook_xml = "xl/workbook.xml"             // Componente essencial do .xlsx
        $python_import = /import\s+[a-zA-Z_][a-zA-Z0-9_]*/       // Padrão de importação do Python
        $python_def = /def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(/       // Definição de função em Python
        $python_class = /class\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(/    // Definição de classe em Python
        $python_if = /if\s+[a-zA-Z_][a-zA-Z0-9_]*\s*:/           // Declaração if em Python
        $python_for = /for\s+[a-zA-Z_][a-zA-Z0-9_]*\s+in\s+/     // Declaração for em Python
        $python_while = /while\s+[a-zA-Z_][a-zA-Z0-9_]*\s*:/     // Declaração while em Python

    condition:
        $xlsx_header at 0 and
        $workbook_xml and
        any of ($python_import, $python_def, $python_class, $python_if, $python_for, $python_while)
}
