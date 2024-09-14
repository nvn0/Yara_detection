import pefile

# Caminho do arquivo .exe
exe_path = r"C:\Users\nunoc\Desktop\start-apps.exe"

# Carrega o arquivo PE
pe = pefile.PE(exe_path)

# Exibe informações gerais do cabeçalho
print("=== Informações Gerais do Ficheiro PE ===")
print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
print(f"TimeDateStamp: {hex(pe.FILE_HEADER.TimeDateStamp)}")
print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")

# Exibe as seções do executável
print("\n=== Seções ===")
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
