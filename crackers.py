#!/usr/bin/env python

import urllib, re, sys, optparse, hashlib
from bs4 import BeautifulSoup
from passlib.hash import phpass

#Author: Everton a.k.a XGU4RD14N && Mateus Lino a.k.a Dctor
#fb: https://www.facebook.com/hatbashbr/

def banner():
    print " |   |       |   __ \                             |            "
    print " |   |  _` | __| |   |  _ \  __|  __| |   | __ \  __|  _ \  __|"
    print " ___ | (   | |   |   |  __/ (    |    |   | |   | |    __/ |   "
    print "_|  _|\__,_|\__|____/ \___|\___|_|   \__, | .__/ \__|\___|_|   "
    print "                                     ____/ _|                  "
    print ""
    print "Author: Everton a.k.a XGU4RD14N - HatBashBR"
    print "Members HatBashBR: Mateus a.k.a Dctor, Junior a.k.a ASTAROTH, Johnny a.k.a UrdSys, No One, Geovane, RHood"
    print "fb.com/hatbashbr"
    print "github.com/hatbashbr"
    print ""
banner()

word = ""

parser = optparse.OptionParser()
parser.add_option("-t", "--type", dest="tipo", help="TIPO(deve estar na lista)", default="None")
parser.add_option("-p", "--pass", dest="hash", help="adicione o hash(opcional)", default="None")
parser.add_option("-w", "--wordlist", dest="wl", help="adicione uma wordlist(opcional)", default="john.txt")
parser.add_option("-s", "--salt", dest="salt", help="adicione um salt(opcional)", default="None")
parser.add_option("-u", "--user", dest="user", help="adicione um nome de usuario(opcional)", default="None")
options, args = parser.parse_args()

def phpasswordpress(hash):
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            d = phpass.verify(pwd, hash)
             
            if(d == True):
                print "WordPress(PHPass)\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print "WordPress(PHPass)\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except ValueError:
        print "WordPress(PHPass)\t\t>>> Hash invalido"
    except Exception as e:
        print "Erro: "+str(e)

def hashsalthashpasssalt(hash, tipo):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+hashlib.md5(pwd).hexdigest()+options.salt).hexdigest()
            else:
                d = hashlib.sha1(options.salt+hashlib.sha1(pwd).hexdigest()+options.salt).hexdigest()
                
            if(d == hash):
                print word+"(salt+"+ word +"(pass)+salt)\t>>> Senha encontrada: "+pwd
                sys.exit()
        print word+"(salt+"+ word +"(pass)+salt)\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def hashsalthashpass(hash, tipo):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+hashlib.md5(pwd).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(options.salt+hashlib.sha1(pwd).hexdigest()).hexdigest()
                
            if(d == hash):
                print word+"(salt+"+ word +"(pass))\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print word+"(salt+"+ word +"(pass))\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltpassuser(hash, tipo, user):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+pwd+user).hexdigest()
            else:
                d = hashlib.sha1(options.salt+pwd+user).hexdigest()
                
            if(d == hash):
                print word+"(salt+pass+username)\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print word+"(salt+pass+username)\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltpasssalt(hash, tipo):
    global word
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+pwd+options.salt).hexdigest()
            else:
                d = hashlib.sha1(options.salt+pwd+options.salt).hexdigest()
                
            if(d == hash):
                print word+"(salt+pass+salt)\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print word+"(salt+pass+salt)\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def passsaltpass(hash, tipo):
    global word
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(pwd+options.salt+pwd).hexdigest()
            else:
                d = hashlib.sha1(pwd+options.salt+pwd).hexdigest()
                
            if(d == hash):
                print word+"(pass+salt+pass)\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print word+"(pass+salt+pass)\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def passsalt(hash, tipo):
    global word
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(pwd+options.salt).hexdigest()
            else:
                d = hashlib.sha1(pwd+options.salt).hexdigest()
                
            if(d == hash):
                print word+"(pass+salt)\t\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print word+"(pass+salt)\t\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltpass(hash, tipo):
    global word
        
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
                print word+"(salt+pass)\t\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print word+"(salt+pass)\t\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def passpass(hash, tipo):
    global word
        
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(pwd+hashlib.md5(pwd).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(pwd+hashlib.sha1(pwd).hexdigest()).hexdigest()
                
            if(d == hash):
                print word +"(pass+"+word+"(pass))\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print word +"(pass+"+word+"(pass))\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
    
def double(hash, tipo):
    global word
        
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(hashlib.md5(pwd).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(hashlib.sha1(pwd).hexdigest()).hexdigest()
                
            if(d == hash):
                print "Double "+ word +"\t\t\t>>> Senha encontrada: "+pwd
                sys.exit()
        print "Double "+ word +"\t\t\t>>> Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
        
def decrypt(hash, tipo):
    global word
        
    if(tipo == 0):
        url = BeautifulSoup(urllib.urlopen("https://md5.gromweb.com/?md5=" + hash), "html.parser")
    else:
        url = BeautifulSoup(urllib.urlopen("https://sha1.gromweb.com/?hash=" + hash), "html.parser")
        
    password = url.find("em", {"class": "long-content string"})
    password = re.sub(re.compile("<.*?>"), "", str(password)).strip()
    if str(password) == "None":
        print word+"\t\t\t\t>>> Senha nao encontrada! :-("
    else:
        print word+"\t\t\t\t>>> Senha encontrada: " + password
        sys.exit()