#pip install yara-python


import yara
import os
import hashlib
#from pathlib import Path
import colorama
from colorama import Back, Fore, Style

#import vt_scan
from vt_scan import file_scan, file_hash_info

from pe_info import file_type, is_pe_file

colorama.init(autoreset=True)


def calcular_hash(file_path, hash_type="sha256"):
    # Escolhe o tipo de hash (md5, sha1, sha256, etc.)
    hash_func = getattr(hashlib, hash_type)()
    
    # Abre o arquivo em modo binário e calcula a hash
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):  # Lê o arquivo em partes
            hash_func.update(chunk)
    
    # Retorna a hash final no formato hexadecimal
    return hash_func.hexdigest()


# V1:

# Compilar a regra a partir do arquivo
#rules = yara.compile(filepath='regra_win_exe.yar')

# compilar várias regras de uma vez
#rules = yara.compile(filepaths={
#    'namespace1': 'example_rule1.yar',
#    'namespace2': 'example_rule2.yar'
#})


# Analisar um ficeheiro:
#matches = rules.match('C:\\Users\\nunoc\\Desktop\\start-apps.exe')
#for match in matches:
#    print(f"Rule: {match.rule}, Strings: {match.strings}")


#######################################################################################


#pasta da regras:
rules_directory = 'regras'



rule_files = {f'rule_{i}': os.path.join(rules_directory, file) 
              for i, file in enumerate(os.listdir(rules_directory)) if file.endswith('.yar')}


# Compile de todas as regras
rules = yara.compile(filepaths=rule_files)


#matches = rules.match(file_to_scan)
#for match in matches:
#    print(f"Rule: {match.rule}")
#    for string in match.strings:
#        print(f"Match at offset {string[0]}: {string[2].decode()}")


################
#matches var:
#{
#  'tags': ['foo', 'bar'],
#  'matches': True,
#  'namespace': 'default',
#  'rule': 'my_rule',
#  'meta': {},
#  'strings': [StringMatch, StringMatch]
#}






###############################



def scan_directory(files_directory):
    count = 0
    # Iterar sobre os ficheiros na pasta
    for root, dirs, files in os.walk(files_directory):
        for file in files:
            file_path = os.path.join(root, file)
            # analisar o ficheiro
            matches = rules.match(file_path)
            fl = calcular_hash(file_path)
    
            vt = file_hash_info(fl)
            
            vts = file_scan(file_path)
            
            # so pra testes
            #vt = None 
            #vts = None
            
            
            # Processar e imprimir os resultados
            print("---------------------------------------------------------------")
            print(Fore.CYAN + "Scanning file:", file_path)
            print(Fore.YELLOW + "File hash (SHA-256):", fl)
            print("---------------------------------------------------------------")
            if matches: 
                print(Fore.YELLOW + "Yara Rules:")
                for match in matches:
                    print(f"  Rule: {match.rule} - {len(match.strings)} matches ")
                    count += 1
                    #print(f"  Rule: {match.rule} - {len(match.strings)} matches  -> {match.strings}")
                print(Fore.YELLOW + "Rules Matched:", count)
                count = 0
            print("-----------------------")
            print(Fore.YELLOW + "VirusTotal analysis:")
            print(Fore.YELLOW + "Hash search:", vt.last_analysis_stats)
            if vt.last_analysis_stats['malicious'] > 30:
                print(Fore.RED + "Dangerous")
            elif vt.last_analysis_stats['malicious'] < 14 and vt.last_analysis_stats['malicious'] > 5:
                print(Fore.YELLOW + "Suspicious, but maybe not dangerous needs more analysis")
            elif vt.last_analysis_stats['malicious'] <= 5 :
                print(Fore.GREEN + "0 or just a few engines have flagged this as malicious. Please note, this does not guarantee that the file is not malicious.")
            try:    
                print(Fore.YELLOW + "File_scan:", vts)  
            except:
                print("")



if __name__ == "__main__":

    MULTI_PE_ANALYSE = False

    #Analisar pasta:
    files_directory = r'C:\analise'
    #files_directory = '/caminho/para/ficheiros' # linux

    scan_directory(files_directory)

    ficheiros = [os.path.join(files_directory,f) for f in os.listdir(files_directory) if os.path.isfile(os.path.join(files_directory, f))]


    #print(ficheiros)
    if len(ficheiros) == 1 and MULTI_PE_ANALYSE == False:
        print(Fore.YELLOW +  "\n============================ File Type: ============================")
        file_type(ficheiros[0])

        print(Fore.YELLOW + "\n============================ PE Info: ============================")
        is_pe_file(ficheiros[0])
    else:
        print(f"A pasta tem {len(ficheiros)} ficheiros.")

    # If are various PE files in the directory the output can be too long andand hard to read
    if MULTI_PE_ANALYSE == True:
        for f in ficheiros:
            print(Fore.YELLOW +  "\n============================ File Type: ============================")
            file_type(f)

            print(Fore.YELLOW + "\n============================ PE Info: ============================")
            is_pe_file(f)


    print("---------------------------------------------------------------")
    print("Scan completed.")

