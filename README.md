# HatDecrypt
MD5, SHA1 and WordPress Decryptor

# Dependencies
You will need to install the bs4 and the passlib library:
pip install bs4 passlib<br />
or download at
https://pypi.python.org/pypi/beautifulsoup4<br />
https://pypi.python.org/pypi/passlib

# Types List
0 = MD5<br />
1 = SHA1<br />
2 = WordPress

# Options
  -h, --help            show this help message and exit<br />
  -t TIPO, --type=TIPO  TIPO(deve estar na lista)<br />
  -p HASH, --pass=HASH  adicione o hash<br />
  -w WL, --wordlist=WL  adicione uma wordlist<br />
  -s SALT, --salt=SALT  adicione um salt<br />
  -u USER, --user=USER  adicione um nome de usuario(opcional)<br />
  -l LIST, --list=LIST  adicione uma lista de hashs

# Usage
Default<br />
python hatdecrypter.py -t TIPO -p HASH<br />

Salted<br />
python hatdecrypter.py -t TIPO -p HASH -s SALT<br />

WordPress<br />
Windows: python hatdecrypter.py -t 2 -p HASH<br />
Linux: python hatdecrypter.py -t 2 -p 'HASH'<br />

# ScreenShots
<img src='http://imgur.com/IIsLF4e.png' /><br />
<img src='http://imgur.com/7pIVCaR.png' /><br />
<img src='http://imgur.com/PERPWs6.png' /><br />
<img src='http://imgur.com/W3VJOqm.png' /><br />