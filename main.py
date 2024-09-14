import yara
import os
import colorama
from colorama import Back, Fore, Style

colorama.init(autoreset=True)

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



# Iterar sobre os ficheiros na pasta
for root, dirs, files in os.walk(files_directory):
    for file in files:
        file_path = os.path.join(root, file)
        # analisar o ficheiro
        matches = rules.match(file_path)
        # Processar e imprimir os resultados se houver correspondências
        if matches:
            print(Fore.CYAN + f'Scanning file: {file_path}')
            for match in matches:
                print(f"  Rule: {match.rule} - {len(match.strings)} matches ")
                #print(f"  Rule: {match.rule} - {len(match.strings)} matches  -> {match.strings}")
                





