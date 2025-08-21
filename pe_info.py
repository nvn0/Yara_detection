#pip install pefile
import pefile
import mimetypes
import sys

argumento = None

if len(sys.argv) > 1:
    argumento = sys.argv[1]
    print("\nArgumento recebido:", argumento)
else:
    print("Nenhum argumento fornecido.")


# Este script verifica se um ficheiro é um executavel windows mesmo que tenha outra extensão de ficheiro

# Caminho do arquivo .exe
pre_exe_path = r"C:\Users\nunoc\Desktop\analise\experiencias - Copy.png"

if argumento != None:
    exe_path = rf"{argumento}"
else:
    exe_path = pre_exe_path
    
assert exe_path, 'Nenhum caminho recebido'

print(exe_path)

tipo, encoding = mimetypes.guess_type(exe_path)
print("\nFile type (based on extension):", tipo)



#primeiros bytes do ficheiro:
with open(exe_path, "rb") as f:
    primeiros_bytes = f.read(256)  # lê os primeiros 256 bytes
    print(f"\nFirst bytes:{primeiros_bytes}")
    print(f"\nFirst bytes:{primeiros_bytes.hex()}")



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
