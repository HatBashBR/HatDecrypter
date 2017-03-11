import urllib, re, sys
from bs4 import BeautifulSoup
import optparse

#Author: Everton a.k.a XGU4RD14N && Mateus Lino a.k.a Dctor
#fb: https://www.facebook.com/hatbashbr/

def md5Decrypt(hash):
    print "MD5 Decrypter"
    if(hash == "None"):
        hash = raw_input("Digite o hash: ")
    url = BeautifulSoup(urllib.urlopen("https://md5.gromweb.com/?md5=" + hash), "html.parser")
    password = url.find("em", {"class": "long-content string"})
    password = re.sub(re.compile("<.*?>"), "", str(password)).strip()
    if str(password) == "None":
        print "Senha nao encontrada! :-("
    else:
        print "Senha: " + password

def sha1Decrypt(hash):
    print"SHA1 Decrypter"
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
        md5Decrypt(options.hash)
    elif(type == 1):
        sha1Decrypt(options.hash)
    else:
        parser.print_help()
        sys.exit()
except Exception as e:
    print "Erro: "+str(e)