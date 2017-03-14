#!/usr/bin/env python

import crackers, threading, time, itertools
from crackers import *

def wordpress(hash):
    wp = threading.Thread(target=phpasswordpress(hash)).start()

def saltanduser(hash, type):
    spu   = threading.Thread(target=saltpassuser(hash, type, options.user)).start()
    hshpu = threading.Thread(target=hashsalthashpassuser(hash, type, options.user)).start()
    
def withoutsalt(hash, type):
    db = threading.Thread(target=double(hash, type)).start()
    pp = threading.Thread(target=passpass(hash, type)).start()
    df = threading.Thread(target=decrypt(hash, type)).start()
    
def withsalt(hash, type):
    sp     = threading.Thread(target=saltpass(hash, type)).start()
    ps     = threading.Thread(target=passsalt(hash, type)).start()
    psp    = threading.Thread(target=passsaltpass(hash, type)).start()
    sps    = threading.Thread(target=saltpasssalt(hash, type)).start()
    hshp   = threading.Thread(target=hashsalthashpass(hash, type)).start()
    hshps  = threading.Thread(target=hashsalthashpasssalt(hash, type)).start()
    hsehps = threading.Thread(target=hashsaltehashpasssalt(hash, type)).start()
    hsehsp = threading.Thread(target=hashsaltehashsaltpass(hash, type)).start()


try:
    if options.tipo == "None":
        print "Voce precisa definir um tipo de hash!"
        parser.print_help()
        sys.exit()

    type = int(options.tipo)
    if(type < 0 and type > 2):
        print "Tipo de hash invalido!"
        sys.exit()
        
    if(type == 0):
        crackers.word = "MD5"
    elif(type == 1):
        crackers.word = "SHA1"
        
    if(options.hash == "None"):
        hash = raw_input("Digite o hash: ")
    else:
        hash = options.hash
    
    if(type == 2):
        print "########## Tentando metodos WordPress ##########"
        wp = threading.Thread(target=wordpress(hash)).start()
    else:
        if(options.salt != "None" and options.user == "None"):
            print "########## Tentando metodos com salt ##########"
            ws = threading.Thread(target=withsalt(hash, type)).start()
            print ""
        elif(options.salt != "None" and options.user != "None"):
            print "########## Tentando metodos com salt e user ##########"
            sau = threading.Thread(target=saltanduser(hash, type)).start()
            print ""
        print "########## Tentando metodos sem salt ##########"
        wos = threading.Thread(target=withoutsalt(hash, type)).start()
        
except Exception as e:
    print "Erro: "+str(e)