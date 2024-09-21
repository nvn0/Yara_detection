import yara
import os
import hashlib
import colorama
from colorama import Back, Fore, Style

from vt_scan import file_scan, file_hash_info

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


#Analisar pasta:
files_directory = r'C:\Users\nunoc\Desktop\analise'
#files_directory = '/caminho/para/ficheiros' # linux


count = 0
# Iterar sobre os ficheiros na pasta
for root, dirs, files in os.walk(files_directory):
    for file in files:
        file_path = os.path.join(root, file)
        # analisar o ficheiro
        matches = rules.match(file_path)
        fl = calcular_hash(file_path)
  
        vt = file_hash_info(fl)
        #vts = file_scan(file_path)
        
        # Processar e imprimir os resultados
        print("---------------------------------------------------------------")
        print(Fore.CYAN + f'Scanning file: {file_path}')
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
        print(Fore.YELLOW + " VirusTotal analysis:")
        print(Fore.YELLOW + "Hash search:", vt.last_analysis_stats)
        if vt.last_analysis_stats['malicious'] > 30:
            print(Fore.RED + "Dangerous")
        elif vt.last_analysis_stats['malicious'] < 14 and vt.last_analysis_stats['malicious'] > 5:
            print(Fore.YELLOW + "Suspicious, but maybe not dangerous needs more analysis")
        elif vt.last_analysis_stats['malicious'] =< 5 :
            print(Fore.Green + "0 or just a few engines have flagged this as malicious. Please note, this does not guarantee that the file is not malicious.")
        try:    
            print(Fore.YELLOW + "File_scan:", vts)  
        except:
            print("")








