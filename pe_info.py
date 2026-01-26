#pip install pefile
import pefile
import mimetypes
import sys

# also known as magic numbers/bytes
file_signature_dict = {"4d5a":"exe file", "7f454c46":"elf file", "d0cf11e0a1b11ae1":"msi or windows document file", "2321":"shebang script file", "494433":"mp3 file", 
"0efeff":"txt/others file", "89504e470d0a1a0a":"png file"}



def file_type(exe_path):
    tipo, encoding = mimetypes.guess_type(exe_path)
    print(f"\nFile encoding: {encoding}")
    print("\nFile type (based on extension):", tipo)


    first_file_bytes = ""

    #primeiros bytes do ficheiro:
    with open(exe_path, "rb") as f:
        primeiros_bytes = f.read(256)  # lê os primeiros 256 bytes
        print(f"\nFirst bytes:{primeiros_bytes}")
        print(f"\nFirst bytes:{primeiros_bytes.hex()}")
        first_file_bytes = primeiros_bytes.hex()


    for i in file_signature_dict:
        if i in str(first_file_bytes):
            print(f"\nSecond validation: Magic bytes in the file correspond to: {file_signature_dict[i]}")
            

def is_pe_file(exe_path):

    # Carrega o arquivo PE
    try:
        pe = pefile.PE(exe_path)
    except pefile.PEFormatError:
        print("\nErro - O ficheiro não é um binário/executavel windows")
        exit()


    # Exibe informações gerais do cabeçalho
    print("\n========= Informações Gerais do Ficheiro PE =========")
    print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
    print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"TimeDateStamp: {hex(pe.FILE_HEADER.TimeDateStamp)}")
    print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")

    # Exibe as secções do executável
    print("\n============ Secções ============")
    for section in pe.sections:
        print(f"Nome: {section.Name.decode('utf-8').strip()}")
        print(f"Virtual Size: {hex(section.Misc_VirtualSize)}")
        print(f"Virtual Address: {hex(section.VirtualAddress)}")
        print(f"Raw Size: {hex(section.SizeOfRawData)}")
        print(f"Pointer to Raw Data: {hex(section.PointerToRawData)}\n")


    # Exibe as funções exportadas
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("\n=== Funções Exportadas ===")
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"Função exportada: {symbol.name.decode('utf-8')}")





    # Exibe as funções importadas (ex: APIs do Windows)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("\n=== Funções Importadas (APIs do Windows) ===")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"\nDLL: {entry.dll.decode('utf-8')}")
            for func in entry.imports:
                if func.name is not None:
                    print(f"\t{func.name.decode('utf-8')}")
                else:
                    # Quando a função não tem nome (importação por ordinal)
                    print(f"\tOrdinal: {func.ordinal}")

    # Fecha o arquivo PE
    pe.close()



if __name__== "__main__":
    argumento = None

    if len(sys.argv) > 1:
        argumento = sys.argv[1]
        print("\nArgumento recebido:", argumento)
    else:
        print("Nenhum argumento fornecido.")


    # Este script verifica se um ficheiro é um executavel windows mesmo que tenha outra extensão de ficheiro

    # Caminho do arquivo .exe
    default_exe_path = r"C:\Users\folder\file.exe"

    if argumento != None:
        exe_path = rf"{argumento}"
    else:
        exe_path = default_exe_path
        
    assert exe_path, 'Nenhum caminho recebido'

    print(exe_path)

    file_type(exe_path)

    is_pe_file(exe_path)
