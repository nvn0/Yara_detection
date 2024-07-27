rule DetectDocxWithMacros
{
    meta:
        description = "Detecta a presença de macros em arquivos .docx"
        author = "ChatGPT"
        date = "2024-07-20"
        version = "1.0"

    strings:
        $docx_header = { 50 4B 03 04 }                // Assinatura de arquivo ZIP
        $vba_project = "word/vbaProject.bin"          // Arquivo que pode conter macros VBA
        $rels_vba_project = "word/_rels/vbaProject.bin.rels" // Arquivo de relacionamentos de macros

    condition:
        $docx_header at 0 and
        ($vba_project or $rels_vba_project)
}
