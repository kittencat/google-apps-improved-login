from base64 import b64encode, b64decode
from zlib import decompress
from xml.dom import minidom
import time
import re
import os
import random
import hashlib
import ds_settings
import gdata.alt.appengine
import gdata.apps.service
import gdata.apps.groups.service
import gdata.apps.adminsettings.service
from google.appengine.ext.webapp import template
from gdata.tlslite.utils.RSAKey import RSAKey
from gdata.tlslite.utils.cryptomath import numberToBase64
import gdata.tlslite.utils.compat
import gdata.tlslite.utils.keyfactory
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ
from Crypto.Util.number import inverse
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
import sys

def putGoogleSSO(gailUrl, pubkey):
  domain = os.environ['AUTH_DOMAIN']
  email = ds_settings.getSetting('adminuser')+'@'+domain
  password = ds_settings.getSetting('adminpass')
  admin = gdata.apps.adminsettings.service.AdminSettingsService(email=email, domain=domain, password=password)
  try:
    admin.ProgrammaticLogin()
  except gdata.service.BadAuthentication:
    return(2)
  pubkey = b64encode(pubkey)
  admin.UpdateSSOKey(pubkey)
  admin.UpdateSSOSettings(enableSSO=True, samlSignonUri=gailUrl,
                          samlLogoutUri=gailUrl,
                          changePasswordUri=gailUrl+'password')

def GetGooglePubKey(self):
  domain = os.environ['AUTH_DOMAIN'] 
  email = ds_settings.getSetting('adminuser')+'@'+domain
  password = ds_settings.getSetting('adminpass')
  admin = gdata.apps.adminsettings.service.AdminSettingsService(email=email, domain=domain, password=password)
  try:
    admin.ProgrammaticLogin()
    googlekey = admin.GetSSOKey()
    oid = ASN1Sequence(univ.ObjectIdentifier('1.2.840.113549.1.1.1'), univ.Null())
    key = ASN1Sequence(univ.Integer(googlekey['modulus']), univ.Integer(googlekey['exponent']))
    binkey = BytesToBin(encoder.encode(key))
    pubkey = univ.BitString("'%s'B" % binkey)
    seq = ASN1Sequence(oid, pubkey)
    pubkeydata = encoder.encode(seq)
  except gdata.service.BadAuthentication:
    pubkeydata = 'failed'
  return pubkeydata

def ASN1Sequence(*vals):
  seq = univ.Sequence()
  for i in range(len(vals)):
    seq.setComponentByPosition(i, vals[i])
  return seq

def BytesToBin(bytes):
  return "".join([_PadByte(IntToBin(ord(byte))) for byte in bytes])

def _PadByte(bits):
  r = len(bits) % 8
  return ((8-r) % 8)*'0' + bits

def IntToBin(n):
  if n == 0 or n == 1:
    return str(n)
  elif n % 2 == 0:
    return IntToBin(n/2) + "0"
  else:
    return IntToBin(n/2) + "1"

def generatePrivkey (self):
  #r = Randomizer()
  k = RSA.generate(2048, os.urandom)
  s = univ.Sequence()
  s.setComponentByPosition(0, univ.Integer('0'))
  s.setComponentByPosition(1, univ.Integer(k.n))
  s.setComponentByPosition(2, univ.Integer(k.e))
  s.setComponentByPosition(3, univ.Integer(k.d))
  s.setComponentByPosition(4, univ.Integer(k.p))
  s.setComponentByPosition(5, univ.Integer(k.q))
  s.setComponentByPosition(6, univ.Integer(k.d % (k.p-1)))
  s.setComponentByPosition(7, univ.Integer(k.d % (k.q-1)))
  s.setComponentByPosition(8, univ.Integer(inverse(k.q, k.p)))

  data = encoder.encode(s)
  bdata = b64encode(data)
  maxlen = 64

  privkey = "-----BEGIN RSA PRIVATE KEY-----\n"
  while len(bdata) > maxlen:
    x = bdata[:maxlen]
    privkey += x+"\n"
    bdata = bdata[maxlen:]
  privkey += bdata
  privkey += "\n-----END RSA PRIVATE KEY-----"
  return privkey

def getPubkey(self, privkey):
  k =  gdata.tlslite.utils.keyfactory.parsePEMKey(privkey, private=True)
  oid = ASN1Sequence(univ.ObjectIdentifier('1.2.840.113549.1.1.1'), univ.Null())
  key = ASN1Sequence(univ.Integer(k.n), univ.Integer(k.e))
  binkey = BytesToBin(encoder.encode(key))
  pubkey = univ.BitString("'%s'B" % binkey)
  seq = ASN1Sequence(oid, pubkey)
  pubkeydata = encoder.encode(seq)
  return pubkeydata

def unpackSAMLRequest (self, SAMLRequest):
  #Takes a base64 and zlib compressed SAMLRequest and returns
  #a dict of attributes

  domain = os.environ['AUTH_DOMAIN'] 
  try:
    SAMLRequest = b64decode(SAMLRequest)
  except:
    gailRedirect(self, 'https://mail.google.com/a/'+domain)
  try:
    SAMLRequest = decompress(SAMLRequest, -8)
  except:
    gailRedirect(self, 'https://mail.google.com/a/'+domain)
  try:
    requestxml = minidom.parseString(SAMLRequest)
  except:
    gailRedirect(self, 'https://mail.google.com/a/'+domain)
  requestdateString = requestxml.firstChild.attributes['IssueInstant'].value + ' UTC' # Google doesn't specify but it's UTC
  requestdate = time.mktime(time.strptime(requestdateString, "%Y-%m-%dT%H:%M:%SZ %Z"))
  now = time.mktime(time.gmtime())
  return {
         'requestage': now - requestdate,
         'acsurl': requestxml.firstChild.attributes['AssertionConsumerServiceURL'].value,
         'providername': requestxml.firstChild.attributes['ProviderName'].value,
         'requestid': requestxml.firstChild.attributes['ID'].value
         }

def userCanBecomeUser (apps, username, loginname):
  # Takes a apps resource, username and loginname.  Checks to see if username has rights
  # to login as loginname using ADMINS_BECOME_USER or USERS_BECOME_USERS.  Returns True/False.
  
  if ds_settings.getSetting('adminsbecomeusers').lower() == 'true':
    try:
      LookupUser = apps.RetrieveUser(username)
      if LookupUser.login.admin == 'true':
        return True
    except gdata.apps.service.AppsForYourDomainException , e:
      pass
  if ds_settings.getSetting('usersbecomeusers').lower() == 'true':
    # Only admins can do group lookups via prov. API so we must login as one
    domain = os.environ['AUTH_DOMAIN'] 
    adminuser = ds_settings.getSetting('adminuser')
    adminpass = ds_settings.getSetting('adminpass') 
    groupsadmin = gdata.apps.groups.service.GroupsService(adminuser+'@'+domain, domain=domain, password=adminpass)
    gdata.alt.appengine.run_on_appengine(groupsadmin, store_tokens=True, single_user_mode=True)
    try:
      groupsadmin.ProgrammaticLogin()
    except gdata.service.BadAuthentication:
      gailRedirect(self, '/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=Invalid%20GAIL%20settings.%20Please%20talk%20to%20your%20network%20administrator.')
    lists = groupsadmin.RetrieveGroups(username)
    for group in lists:
      if re.match('.*-become@'+domain, group['groupId'].lower()):
        #see if loginname matches this group name (minus the -become)
        #or if loginname is a member of this group (minus the -become)
        if group['groupId'].lower() == loginname.lower()+'-become@'+domain:
          return True
        elif groupsadmin.IsMember(loginname, group['groupId'][0:(group['groupId'].find('-become@'))]) or groupsadmin.IsMember('*', group['groupId'][0:(group['groupId'].find('-become@'))]):
          return True
  return False
  
def createAutoPostResponse (self, request, username):
    # takes a SAMLRequest and the username to sign in.  Returns
    # signed XML SAMLResponse.  Will redirect user to login page
    # if SAMLRequest has expired.
    
    domain = os.environ['AUTH_DOMAIN'] 
    templatepath = os.path.join(os.path.dirname(__file__), 'templates')
    requestdata = unpackSAMLRequest(self, request)
    age = requestdata['requestage']
    if (age < 0) or (age > 590): # is our SAMLRequest old or invalid?
      gailRedirect(self, 'https://mail.google.com/a/' + domain)
    ranchars = 'abcdefghijklmnop'
    responseid = ''
    assertid = ''
    for i in range(1, 40):
      responseid += ranchars[random.randint(0,15)]
      assertid += ranchars[random.randint(0,15)]
    template_values = {
      'assertid': assertid,
      'responseid': responseid,
      'username': username,
      'domain': domain,
      'issueinstant': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
      'authninstant': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
      'acsurl': requestdata['acsurl'],
      'providername': requestdata['providername'],
      'requestid': requestdata['requestid'],
      'notbefore': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(time.time()) - (5 * 60))),  # 5 minutes ago
      'notafter': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(time.time()) + (10 * 60)))  # 10 minutes from now
      }
    responsepath = os.path.join(templatepath, 'response.xml')
    digestpath = os.path.join(templatepath, 'digest.xml')
    digestPart = template.render(digestpath, template_values)
    digestPart = digestPart[0:(len(digestPart) - 2)] # template adds \n\n at end of string, remove it
    digestSha1 = hashlib.sha1(digestPart)
    digest = b64encode(digestSha1.digest())
    template_values.update({'digest': digest})
    sipath = os.path.join(templatepath, 'response-signature-signedinfo.xml')
    signedInfo = template.render(sipath, template_values)
    signedInfo = signedInfo[0:(len(signedInfo) - 1)] # get rid of last newline
    key = gdata.tlslite.utils.keyfactory.parsePEMKey(ds_settings.getSetting('privkey'), private=True)
    signvalue = b64encode(key.hashAndSign(gdata.tlslite.utils.compat.stringToBytes(signedInfo)))      
    modulus = numberToBase64(key.n)
    exponent = numberToBase64(key.e)
    template_values.update({'signvalue': signvalue, 'modulus': modulus, 'exponent': exponent})
    responsepath = os.path.join(templatepath, 'response.xml')
    signedresponse = b64encode(template.render(responsepath, template_values))
    autopostpath = os.path.join(templatepath, 'autopost.html')
    autopost_values = {
      'acsurl': requestdata['acsurl'],
      'signedresponse': signedresponse,
      'relaystate': self.request.get('RelayState') # template takes care of escaping for IE
      }
    return template.render(autopostpath, autopost_values)
    
def gailRedirect (self, url):

  #Takes a URL and redirects the user there then exits Python.
  #We do this because AppEngine's self.redirect() doesn't seem to work 100%

  print ('''Content-Type: text/html

<html>
<head>
  <meta http-equiv="refresh" content="0;url=%s">
</head>
<body>
</body>
</html>''' % (url,))
  exit(0)
