#!/usr/bin/env python

import crackers, threading
from crackers import *

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
    
    if(type == 2):
        print "########## Tentando metodos WordPress ##########"
        wp = threading.Thread(target=phpasswordpress(options.hash)).start()
    else:
        if(options.salt != "None" and options.user == "None"):
            print "########## Tentando metodos com salt ##########"
            sp  = threading.Thread(target=saltpass(options.hash, type)).start()
            ps  = threading.Thread(target=passsalt(options.hash, type)).start()
            psp = threading.Thread(target=passsaltpass(options.hash, type)).start()
            sps = threading.Thread(target=saltpasssalt(options.hash, type)).start()
            print ""
        elif(options.salt != "None" and options.user != "None"):
            print "########## Tentando metodos com salt ##########"
            spu  = threading.Thread(target=saltpassuser(options.hash, type, options.user)).start()
            print ""
        print "########## Tentando metodos sem salt ##########"
        db = threading.Thread(target=double(options.hash, type)).start()
        pp = threading.Thread(target=passpass(options.hash, type)).start()
        df = threading.Thread(target=decrypt(options.hash, type)).start()
except Exception as e:
    print "Erro: "+str(e)