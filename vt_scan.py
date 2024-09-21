import vt
from dotenv import load_dotenv


# Load from .env
load_dotenv('.env')
TOKEN = open(".env", "r").read()

def conn():
    client = vt.Client(TOKEN)
    return client


def file_scan(path):
    try:
        client = conn()
        with open(path, "rb") as f:
            analysis = client.scan_file(f, wait_for_completion=True)
    except:
        print("ERRO - Ocorreu um problema de conexão com o VirusTotal")
    else:
        client.close()
        return analysis
    


def url_scan(url):

    urls = client.get_object("/urls/{}", url)
    return urls



def file_hash_info(hash):
    try:
        client = conn()
        file = client.get_object(f"/files/{hash}")
    except:
        print("ERRO - Ocorreu um problema de conexão com o VirusTotal")
    else:
        client.close()
        return file
 





