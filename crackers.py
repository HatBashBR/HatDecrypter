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
parser.add_option("-p", "--pass", dest="hash", help="adicione o hash", default="None")
parser.add_option("-w", "--wordlist", dest="wl", help="adicione uma wordlist", default="john.txt")
parser.add_option("-s", "--salt", dest="salt", help="adicione um salt", default="None")
parser.add_option("-u", "--user", dest="user", help="adicione um nome de usuario", default="None")
parser.add_option("-l", "--list", dest="list", help="adicione uma lista de hashs", default="")
options, args = parser.parse_args()

#WordPress
def wpPHPass(hash):
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            d = phpass.verify(pwd, hash)
             
            if(d == True):
                print "WordPress(PHPass)\t\t[+] Senha encontrada: "+pwd
                return
        print "WordPress(PHPass)\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except ValueError:
        print "WordPress(PHPass)\t\t Hash invalido"
    except Exception as e:
        print "Erro: "+str(e)

#With User
def userTwo(hash, tipo, user):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+hashlib.md5(pwd).hexdigest()+user).hexdigest()
            else:
                d = hashlib.sha1(options.salt+hashlib.sha1(pwd).hexdigest()+user).hexdigest()
                
            if(d == hash):
                print word+"(salt+"+ word +"(pass)+user)\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+"+ word +"(pass)+user)\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def userOne(hash, tipo, user):
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
                print word+"(salt+pass+user)\t\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+pass+user)\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

#With Salt
def saltNine(hash, tipo):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+hashlib.md5(hashlib.md5(pwd).hexdigest()+options.salt).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(options.salt+hashlib.sha1(hashlib.sha1(pwd).hexdigest()+options.salt).hexdigest()).hexdigest()
                
            if(d == hash):
                print word+"(salt+"+ word +"("+ word +"(pass)+salt))\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+"+ word +"("+ word +"(pass)+salt))\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
    
def saltEight(hash, tipo):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+hashlib.md5(options.salt+pwd).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(options.salt+hashlib.sha1(options.salt+pwd).hexdigest()).hexdigest()
                
            if(d == hash):
                print word+"(salt+"+ word +"(salt+pass))\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+"+ word +"(salt+pass))\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
        
def saltSeven(hash, tipo):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+hashlib.md5(pwd+options.salt).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(options.salt+hashlib.sha1(pwd+options.salt).hexdigest()).hexdigest()
                
            if(d == hash):
                print word+"(salt+"+ word +"(pass+salt))\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+"+ word +"(pass+salt))\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
    
def saltSix(hash, tipo):
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
                print word+"(salt+"+ word +"(pass)+salt)\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+"+ word +"(pass)+salt)\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltFive(hash, tipo):
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
                print word+"(salt+"+ word +"(pass))\t\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+"+ word +"(pass))\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltFour(hash, tipo):
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
                print word+"(salt+pass+salt)\t\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+pass+salt)\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltThree(hash, tipo):
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
                print word+"(pass+salt+pass)\t\t[+] Senha encontrada: "+pwd
                return
        print word+"(pass+salt+pass)\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltTwo(hash, tipo):
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
                print word+"(pass+salt)\t\t\t[+] Senha encontrada: "+pwd
                return
        print word+"(pass+salt)\t\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def saltOne(hash, tipo):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(options.salt+pwd).hexdigest()
            else:
                d = hashlib.sha1(options.salt+pwd).hexdigest()
                
            if(d == hash):
                print word+"(salt+pass)\t\t\t[+] Senha encontrada: "+pwd
                return
        print word+"(salt+pass)\t\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

#Without Salt
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
                print word +"(pass+"+word+"(pass))\t\t[+] Senha encontrada: "+pwd
                return
        print word +"(pass+"+word+"(pass))\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def sextuple(hash, tipo):
    global word
        
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(hashlib.md5(hashlib.md5(hashlib.md5(hashlib.md5(hashlib.md5(pwd).hexdigest()).hexdigest()).hexdigest()).hexdigest()).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(hashlib.sha1(hashlib.sha1(hashlib.sha1(hashlib.sha1(hashlib.sha1(pwd).hexdigest()).hexdigest()).hexdigest()).hexdigest()).hexdigest()).hexdigest()
                
            if(d == hash):
                print "Sextuple "+ word +"\t\t\t[+] Senha encontrada: "+pwd
                return
        print "Sextuple "+ word +"\t\t\t[+] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def quintuple(hash, tipo):
    global word
        
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(hashlib.md5(hashlib.md5(hashlib.md5(hashlib.md5(pwd).hexdigest()).hexdigest()).hexdigest()).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(hashlib.sha1(hashlib.sha1(hashlib.sha1(hashlib.sha1(pwd).hexdigest()).hexdigest()).hexdigest()).hexdigest()).hexdigest()
                
            if(d == hash):
                print "Quintuple "+ word +"\t\t\t[+] Senha encontrada: "+pwd
                return
        print "Quintuple "+ word +"\t\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def quadruple(hash, tipo):
    global word
        
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(hashlib.md5(hashlib.md5(hashlib.md5(pwd).hexdigest()).hexdigest()).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(hashlib.sha1(hashlib.sha1(hashlib.sha1(pwd).hexdigest()).hexdigest()).hexdigest()).hexdigest()
                
            if(d == hash):
                print "Quadruple "+ word +"\t\t\t[+] Senha encontrada: "+pwd
                return
        print "Quadruple "+ word +"\t\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def triple(hash, tipo):
    global word
        
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(hashlib.md5(hashlib.md5(pwd).hexdigest()).hexdigest()).hexdigest()
            else:
                d = hashlib.sha1(hashlib.sha1(hashlib.sha1(pwd).hexdigest()).hexdigest()).hexdigest()
                
            if(d == hash):
                print "Triple "+ word +"\t\t\t[+] Senha encontrada: "+pwd
                return
        print "Triple "+ word +"\t\t\t[-] Senha nao encontrada! :-("
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
                print "Double "+ word +"\t\t\t[+] Senha encontrada: "+pwd
                return
        print "Double "+ word +"\t\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)

def decryptwl(hash, tipo):
    global word
    
    try:
        f = open(options.wl)
        for pwd in f.readlines():
            pwd = pwd.strip()
            if(tipo == 0):
                d = hashlib.md5(pwd).hexdigest()
            else:
                d = hashlib.sha1(pwd).hexdigest()
                
            if(d == hash):
                print word+"\t\t\t\t[+] Senha encontrada: " + pwd
                return
        print word+"\t\t\t\t[-] Senha nao encontrada! :-("
    except IOError:
        print "Nao foi possivel abrir sua wordlist, tente novamente."
    except Exception as e:
        print "Erro: "+str(e)
      
def decrypt(hash, tipo):
    global word
    
    try:
        if(tipo == 0):
            url = BeautifulSoup(urllib.urlopen("https://md5.gromweb.com/?md5=" + hash), "html.parser")
        else:
            url = BeautifulSoup(urllib.urlopen("https://sha1.gromweb.com/?hash=" + hash), "html.parser")
            
        password = url.find("em", {"class": "long-content string"})
        password = re.sub(re.compile("<.*?>"), "", str(password)).strip()
        if str(password) == "None":
            print word+"\t\t\t\t[-] Senha nao encontrada! :-("
        else:
            print word+"\t\t\t\t[+] Senha encontrada: " + password
    except IOError:
       decryptwl(hash, tipo)