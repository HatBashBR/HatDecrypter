import urllib, re, sys, optparse, hashlib, threading
from bs4 import BeautifulSoup

#Author: Everton a.k.a XGU4RD14N && Mateus Lino a.k.a Dctor
#fb: https://www.facebook.com/hatbashbr/
word = ""

def passsaltpass(hash, tipo):
    global word
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(pwd+options.salt+pwd).hexdigest()
            else:
                d = hashlib.sha1(pwd+options.salt+pwd).hexdigest()
                
            if(d == hash):
                print word+"(pass+salt+pass) - Senha encontrada: "+pwd
                sys.exit()
        print word+"(pass+salt+pass) - Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def passsalt(hash, tipo):
    global word
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(pwd+options.salt).hexdigest()
            else:
                d = hashlib.sha1(pwd+options.salt).hexdigest()
                
            if(d == hash):
                print word+"(pass+salt) - Senha encontrada: "+pwd
                sys.exit()
        print word+"(pass+salt) - Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltpass(hash, tipo):
    global word
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
                print word+"(salt+pass) - Senha encontrada: "+pwd
                sys.exit()
        print word+"(salt+pass) - Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
        
def double(hash, tipo):
    global word
    
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
        
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(hashlib.md5(pwd).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(hashlib.sha1(pwd).hexdigest()).hexdigest()
                
            if(d == hash):
                print "Double "+ word +" - Senha encontrada: "+pwd
                sys.exit()
        print "Double "+ word +" - Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
        
def decrypt(hash, tipo):
    global word
    
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
        
    if(tipo == 0):
        url = BeautifulSoup(urllib.urlopen("https://md5.gromweb.com/?md5=" + hash), "html.parser")
    else:
        url = BeautifulSoup(urllib.urlopen("https://sha1.gromweb.com/?hash=" + hash), "html.parser")
        
    password = url.find("em", {"class": "long-content string"})
    password = re.sub(re.compile("<.*?>"), "", str(password)).strip()
    if str(password) == "None":
        print word+" - Senha nao encontrada! :-("
    else:
        print word+" - Senha encontrada: " + password
        sys.exit()
        

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
        
    if(type == 0):
        word = "MD5"
    elif(type == 1):
        word = "SHA1"
        
    if(options.salt != "None"):
        print "########## Tentando metodos com salt ##########"
        sp  = threading.Thread(target=saltpass(options.hash, type)).start()
        ps  = threading.Thread(target=passsalt(options.hash, type)).start()
        psp = threading.Thread(target=passsaltpass(options.hash, type)).start()
    elif(options.salt == "None"):
        print "########## Tentando metodos sem salt ##########"
        db = threading.Thread(target=double(options.hash, type)).start()
        df = threading.Thread(target=decrypt(options.hash, type)).start()
    else:
        parser.print_help()
        sys.exit()
except Exception as e:
    print "Erro: "+str(e)