import urllib, re, sys, optparse, hashlib
from bs4 import BeautifulSoup

#Author: Everton a.k.a XGU4RD14N && Mateus Lino a.k.a Dctor
#fb: https://www.facebook.com/hatbashbr/

def md5salt(hash):
    print "########## Tentando - MD5 Salted Decrypter ##########"
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
        
    if(options.salt == "None"):
        print "Para tentar com o MD5 Salted voce precisa definir um salt!"
        sys.exit()
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            d = hashlib.md5(options.salt+pwd).hexdigest()
            if(d == hash):
                print "Senha encontrada: "+pwd
                sys.exit()
        print "Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
    
def md5Decrypt(hash):
    print "########## Tentando - MD5 Decrypter ##########"
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
    url = BeautifulSoup(urllib.urlopen("https://md5.gromweb.com/?md5=" + hash), "html.parser")
    password = url.find("em", {"class": "long-content string"})
    password = re.sub(re.compile("<.*?>"), "", str(password)).strip()
    if str(password) == "None":
        print "Senha nao encontrada! :-("
    else:
        print "Senha: " + password

def sha1salt(hash):
    print "########## Tentando - SHA1 Salted Decrypter ##########"
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
        
    if(options.salt == "None"):
        print "Para tentar com o SHA1 Salted voce precisa definir um salt!"
        sys.exit()
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            d = hashlib.sha1(options.salt+pwd).hexdigest()
            if(d == hash):
                print "Senha encontrada: "+pwd
                sys.exit()
        print "Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def sha1Decrypt(hash):
    print"########## Tentando - SHA1 Decrypter ##########"
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
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

    if(type == 0 and options.salt == "None"):
        md5Decrypt(options.hash)
    elif(type == 0 and options.salt != "None"):
        md5salt(options.hash)
    elif(type == 1 and options.salt == "None"):
        sha1Decrypt(options.hash)
    elif(type == 1 and options.salt != "None"):
        sha1salt(options.hash)
    else:
        parser.print_help()
        sys.exit()
except Exception as e:
    print "Erro: "+str(e)