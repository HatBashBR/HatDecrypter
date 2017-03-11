# HatDecrypt
MD5 and SHA1 Decryptor

# Dependencies
You will need to install the bs4 library:
pip install bs4
or download at https://pypi.python.org/pypi/beautifulsoup4

# Types List
0 = MD5<br />
1 = SHA1

# Options
Options:<br />
  -h, --help            show this help message and exit<br />
  -t TIPO, --type=TIPO  TIPO(deve estar na lista)<br />
  -p HASH, --pass=HASH  adicione o hash(opcional)<br />
  -w WL, --wordlist=WL  adicione uma wordlist(opcional)<br />
  -s SALT, --salt=SALT  adicione um salt(opcional)

# Usage
Default<br />
python hatdecrypter.py -t TIPO<br /><br />

Salted<br />
python hatdecrypter.py -t TIPO -s SALT