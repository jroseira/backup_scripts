#!/usr/bin/env python
#
# HASH MD5 100SEC
# Revela o HASH MD5 usando o metodo Online ou Offline
#
# Por: Marcos Henrique | marcos@100security.com.br
#
# WebSite: www.100security.com.br
#

import sys
import time
import urllib2
import urllib 
import re
import hashlib

if len(sys.argv) < 2:
  print '\nComando:'
  print '\tpython %s --online e99a18c428cb38d5f260853678922e03 ' % sys.argv[0]
  print '\tpython %s --offline e99a18c428cb38d5f260853678922e03 senhas.txt\n'  % sys.argv[0]
  sys.exit(1)

def banner():
  print '''
	...........................................................
	...........................................................
	...........................................................
	....         .............    .................    ........
	....         .............    .................    ........
	.........    .........    ....    .........    ....    ....
	.........    .........    ....    .........    ....    ....
	.........    .........    ....    .........    ....    ....
	.........    .........    ....    .........    ....    ....
	.........    .........    ....    .........    ....    ....
	.........    .........    ....    .........    ....    ....
	.........    .........    ....    .........    ....    ....
	.........    ..............................................
	.........    .............    .................    ........
	.........    .............    .................    ........
	...........................................................
	...........................................................
	...........................................................
	.............. S . E . C . U . R . I . T . Y ..............
	...........................................................
	................. wwww.100security.com.br .................
	...........................................................
	...........................................................

'''

option   = sys.argv[1]
passwd   = sys.argv[2]

if option == '--online':
  if len(passwd) != 32: 
    print '\n[*] Error: "%s" doesn\'t seem to be a valid MD5 hash "32 bit hexadecimal"' % passwd
  else:
    try:
      banner()

# http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php

      def myaddr():
        site = 'http://md5.my-addr.com'
        rest = '/md5_decrypt-md5_cracker_online/md5_decoder_tool.php'
        para = urllib.urlencode({'md5':passwd})
        req  = urllib2.Request(site+rest)
        try:
          fd   = urllib2.urlopen(req, para)
          data = fd.read()
          match= re.search('(Hashed string</span>: )(\w+.\w+)', data)
          if match: print '- WebSite: %s\t\t\t* Senha: %s' % (site, match.group(2))
          else: print '- WebSite: %s\t\t\t  Senha: Nao encontrada!' % site
        except urllib2.URLError:  print '- WebSite: %s \t\t\t  Status: Indisponivel' % site
      myaddr()

# http://www.victorov.su/md5/?md5e=&md5d=%s

      def victorov():
        try:
          site = 'http://www.victorov.su'
          para = '/md5/?md5e=&md5d=%s' % passwd
          req  = urllib2.Request(site+para)
          req.add_header
          opener = urllib2.urlopen(req)
          data = opener.read()
          match = re.search('(<b>)(.+[^>])(</b>)', data)
          if match: print '- WebSite: %s\t\t\t* Senha: %s' % (site, match.group(2))
          else: print '- WebSite: %s\t\t\t  Senha: Nao encontrada!' % site
        except urllib2.URLError:  print '- WebSite: %s \t\t\t  Status: Indisponivel' % site
      victorov()
      
# http://www.md5crack.com/crackmd5.php

      def md5crack():
        site = 'http://www.md5crack.com'
        rest = '/crackmd5.php'
        para = urllib.urlencode({'term':passwd})
        req = urllib2.Request(site+rest)
        try: 
          fd = urllib2.urlopen(req, para)
          data = fd.read()
          match = re.search('(Found: md5)(..)(\w+.\w+)', data)
          if match: print '- WebSite: %s\t\t\t* Senha: %s' % (site, match.group(3))
          else: print '- WebSite: %s\t\t\t  Senha: Nao encontrada!' % site
        except urllib2.URLError: print '- WebSite: %s \t\t\t  Status: Indisponivel' % site
      md5crack()
      
# http://passcracking.com/index.php  

      def passcracking():
        site = 'http://passcracking.com'
        rest = '/index.php'
        para = urllib.urlencode({'datafromuser':passwd})
        req = urllib2.Request(site+rest)
        try:
          fd = urllib2.urlopen(req, para)
          data = fd.read()
          match = re.search(r"(<td bgcolor=#FF0000>)(.+[^<])(</td><td>)", data)
          if match: print '- WebSite: %s\t\t\t* Senha: %s' % (site, match.group(2))
          else: print '- WebSite: %s\t\t\t  Senha: Nao encontrada!' % site
        except urllib2.URLError: print '- WebSite: %s \t\t\t  Status: indisponivel' % site
      passcracking()

# http://www.md5pass.info

      def md5pass():
        site = 'http://www.md5pass.info'
        para = urllib.urlencode({'hash':passwd, 'get_pass':'Get+Pass'})
        req = urllib2.Request(site)
        try:
          fd = urllib2.urlopen(req, para)
          data = fd.read()
          match = re.search('(Senha - <b>)(\w+)', data)
          if match: print '- WebSite: %s\t\t\t* Senha: %s' % (site, match.group(2))
          else: print '- WebSite: %s\t\t\t  Senha: Nao encontrada!' % site
        except urllib2.URLError: print '- WebSite: %s \t\t\t  Status: Indisponivel' % site
      md5pass()

# http://md5decryption.com/

      def md5decryption():
        site = 'http://md5decryption.com'
        para = urllib.urlencode({'hash':passwd,'submit':'Decrypt+It!'})
        req = urllib2.Request(site)
        try:
          fd = urllib2.urlopen(req, para)
          data = fd.read()
          match = re.search(r'(Decrypted Text: </b>)(.+[^>])(</font><br/><center>)', data)
          if match: print '- WebSite: %s\t\t\t* Senha: %s' % (site, match.group(2))
          else: print '- WebSite: %s\t\t\t  Senha: Nao encontrada!' % site
        except urllib2.URLError: print '- WebSite: %s \t\t\t  Status: Indisponivel' % site
      md5decryption()

# http://www.netmd5crack.com/cgi-bin/Crack.py?InputHash=%s

      def cloudcracker():
        site = 'http://www.netmd5crack.com'
        para = '/cgi-bin/Crack.py?InputHash=%s' % passwd
        try:
          req = urllib.urlopen(site+para)
          data = req.read()
          match = re.search(r'<tr><td class="border">[^<]+</td><td class="border">\
          (?P<hash>[^>]+)</td></tr></tbody></table>', data)
          if match: print '- WebSite: %s\t\t\t* Senha: %s' % (site, match.group(hash))
          else: print '- WebSite: %s\t\t\t  Senha: Nao encontrada!' % site
        except urllib2.URLError: print '- WebSite: %s \t\t\t  Status: Indisponivel' % site
      cloudcracker()

# http://www.cloudcracker.net

      def cloudcracker():
        site = 'http://www.cloudcracker.net'
        para = urllib.urlencode({'inputbox':passwd, 'submit':'Crack+MD5+Hash!'})
        req = urllib2.Request(site)
        try:
          fd = urllib2.urlopen(req, para)
          data = fd.read()
          match = re.search('(this.select)(....)(\w+=")(\w+.\w+)', data)
          if match: print '- WebSite: %s\t\t\t* Senha: %s\n' % (site, match.group(4))
          else: print '- WebSite: %s\t\t\t  Senha: Nao encontrada!\n' % site
        except urllib2.URLError: print '- WebSite: %s \t\t\t  Status: Indisponivel' % site
      cloudcracker()

    except KeyboardInterrupt: print '\nPesquisa Cancelada...'
    
# Offline

elif option == '--offline':
  banner()
  try:
    def offline():
      print '- Este pesquisa pode demorar, seja paciente...' 
      dictionary = sys.argv[3]
      dic = {}
      shooter = 0
      try:
        f = open(dictionary, 'rb')
        start = time.time()
        for line in f:
          line = line.rstrip()
          dic[line] = hashlib.md5(line).hexdigest()
        for k in dic.keys(): 
          if passwd in dic[k]:
            stop = time.time()
            global spent
            spent = stop - start
            print '\n- Hash: %s\t\tSenha: %s\t\t\n' % (dic[k], k)
            shooter += 1
        if shooter == 0:  print "\n- A senha nao foi encontrada no arquivo [%s], tente o metodo online!\n" % dictionary
        f.close()
      except IOError: print '\n- Erro: O arquivo %s nao existe!\n' % dictionary
    offline()
  except KeyboardInterrupt: print '\nPesquisa Cancelada...'
  
else: pass 
