rule LongSequencesOfSpacesOrZeros
{
    meta:
        description = "Detecta sequências longas de espaços vazios ou zeros (pode gerar falsos positivos)"
        author = "ChatGPT"
        date = "2024-07-20"
        version = "1.0"

    strings:
        $long_spaces = /\x20{50,}/      // Sequências longas de espaços (caractere 0x20)
        $long_zeros = /\x00{50,}/       // Sequências longas de zeros (caractere 0x00)

    condition:
        $long_spaces or $long_zeros
}
