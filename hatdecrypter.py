#!/usr/bin/env python

import crackers, threading, time, itertools
from crackers import *

def wordpress(hash):
    wp = threading.Thread(target=wpPHPass(hash)).start()

def saltanduser(hash, type):
    spu   = threading.Thread(target=userOne(hash, type, options.user)).start()
    hshpu = threading.Thread(target=userTwo(hash, type, options.user)).start()
    
def withoutsalt(hash, type):
    pp = threading.Thread(target=passpass(hash, type)).start()
    sp = threading.Thread(target=sextuple(hash, type)).start()
    qt = threading.Thread(target=quintuple(hash, type)).start()
    qp = threading.Thread(target=quadruple(hash, type)).start()
    tp = threading.Thread(target=triple(hash, type)).start()
    db = threading.Thread(target=double(hash, type)).start()
    df = threading.Thread(target=decrypt(hash, type)).start()
    
def withsalt(hash, type):
    sp     = threading.Thread(target=saltOne(hash, type)).start()
    ps     = threading.Thread(target=saltTwo(hash, type)).start()
    psp    = threading.Thread(target=saltThree(hash, type)).start()
    sps    = threading.Thread(target=saltFour(hash, type)).start()
    hshp   = threading.Thread(target=saltFive(hash, type)).start()
    hshps  = threading.Thread(target=saltSix(hash, type)).start()
    hsehps = threading.Thread(target=saltSeven(hash, type)).start()
    hsehsp = threading.Thread(target=saltEight(hash, type)).start()
    hshhps = threading.Thread(target=saltNine(hash, type)).start()


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
    
    if(options.list != "" and options.hash != "None"):
        print "Voce nao pode usar '-p' em conjunto com '-l'."
        sys.exit()
    
    if(options.list != ""):
        try:
            f = open(options.list)
            for p in f.readlines():
                p = p.strip()
                print "\n---------- "+ p +" ----------"
                if(type == 2):
                    wp = threading.Thread(target=wordpress(p)).start()
                else:
                    wos = threading.Thread(target=withoutsalt(p, type)).start()
        except IOError:
            print "Nao foi possivel abrir sua lista de hashes, tente novamente!"
    else:
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