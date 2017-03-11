import urllib, re, sys, optparse, hashlib
from bs4 import BeautifulSoup

#Author: Everton a.k.a XGU4RD14N && Mateus Lino a.k.a Dctor
#fb: https://www.facebook.com/hatbashbr/

def salted(hash, tipo):
    word = ""
    if(tipo == 0):
        word = "MD5"
    else:
        word = "SHA1"
        
    print "########## Tentando - " + word + " Salted Decrypter ##########"
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
        
    if(options.salt == "None"):
        print "Para tentar com o " + word + " Salted voce precisa definir um salt!"
        sys.exit()
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+pwd).hexdigest()
            else:
                d = hashlib.sha1(options.salt+pwd).hexdigest()
                
            if(d == hash):
                print "Senha encontrada: "+pwd
                sys.exit()
        print "Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def decrypt(hash, tipo):
    word = ""
    if(tipo == 0):
        word = "MD5"
    else:
        word = "SHA1"
        
    print "########## Tentando - " + word + " Decrypter ##########"
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
        
    if(tipo == 0):
        url = BeautifulSoup(urllib.urlopen("https://md5.gromweb.com/?md5=" + hash), "html.parser")
    else:
        url = BeautifulSoup(urllib.urlopen("https://sha1.gromweb.com/?hash=" + hash), "html.parser")
        
    password = url.find("em", {"class": "long-content string"})
    password = re.sub(re.compile("<.*?>"), "", str(password)).strip()
    if str(password) == "None":
        print "Senha nao encontrada! :-("
    else:
        print "Senha: " + password

parser = optparse.OptionParser()
parser.add_option("-t", "--type", dest="tipo", help="TIPO(deve estar na lista)", default="None")
parser.add_option("-p", "--pass", dest="hash", help="adicione o hash(opcional)", default="None")
parser.add_option("-w", "--wordlist", dest="wl", help="adicione uma wordlist(opcional)", default="john.txt")
parser.add_option("-s", "--salt", dest="salt", help="adicione um salt(opcional)", default="None")
options, args = parser.parse_args()

try:
    if options.tipo == "None":
        print "Voce precisa definir um tipo de hash!"
        parser.print_help()
        sys.exit()

    type = int(options.tipo)
    if(type != 0 and type != 1):
        print "Tipo de hash invalido!"
        sys.exit()
    
    if(options.salt != "None"):
        salted(options.hash, type)
    elif(options.salt == "None"):
        decrypt(options.hash, type)
    else:
        parser.print_help()
        sys.exit()
except Exception as e:
    print "Erro: "+str(e)