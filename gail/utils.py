from base64 import b64encode, b64decode
from zlib import decompress
from xml.dom import minidom
import time
import re
import os
import random
import hashlib
import settings
import gdata.alt.appengine
import gdata.apps.service
import gdata.apps.groups.service
from google.appengine.ext.webapp import template
from gdata.tlslite.utils.RSAKey import RSAKey
import gdata.tlslite.utils.compat
import gdata.tlslite.utils.keyfactory

def unpackSAMLRequest (self, SAMLRequest):
  #Takes a base64 and zlib compresed SAMLRequest and returns
  #a dict of attributes

  try:
    SAMLRequest = b64decode(SAMLRequest)
  except:
    self.redirect('https://mail.google.com/a/'+settings.GAPPS_DOMAIN)
  try:
    SAMLRequest = decompress(SAMLRequest, -8)
  except:
    self.redirect('https://mail.google.com/a/'+settings.GAPPS_DOMAIN)
  try:
    requestxml = minidom.parseString(SAMLRequest)
  except:
    self.redirect('https://mail.google.com/a/'+settings.GAPPS_DOMAIN)
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
  
  if settings.ADMINS_BECOME_USER:
    try:
      LookupUser = apps.RetrieveUser(username)
    except gdata.apps.service.AppsForYourDomainException , e:
      pass
    if LookupUser.login.admin == 'true':
      return True
  if settings.USERS_BECOME_USERS:
    # Only admins can do group lookups via prov. API so we must login as one
    domain = settings.GAPPS_DOMAIN
    groupsadmin = gdata.apps.groups.service.GroupsService(email=settings.ADMIN_USER+'@'+domain, domain=domain, password=settings.ADMIN_PASS)
    gdata.alt.appengine.run_on_appengine(groupsadmin, store_tokens=True, single_user_mode=True)
    try:
      groupsadmin.ProgrammaticLogin()
    except gdata.service.BadAuthentication:
      self.redirect('/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=Invalid%20GAIL%20settings.%20Please%20talk%20to%20your%20network%20administrator.')
    lists = groupsadmin.RetrieveGroups(username)
    canBecome = False
    for group in lists:
      if re.match('.*-become@'+domain, group['groupId'].lower()):
        #see if loginname matches this group name (minus the -become)
        #or if loginname is a member of this group (minus the -become)
        if group['groupId'].lower() == loginname.lower()+'-become@'+domain:
          canBecome = True
        elif groupsadmin.IsMember(loginname, group['groupId'][0:(group['groupId'].find('-become@'))]) or groupsadmin.IsMember('*', group['groupId'][0:(group['groupId'].find('-become@'))]):
          canBecome = True
          break
    return canBecome
  return False
  
def createAutoPostResponse (self, request, username):
    # takes a SAMLRequest and the username to sign in.  Returns
    # signed XML SAMLResponse.  Will redirect user to login page
    # if SAMLRequest has expired.
    
    domain = settings.GAPPS_DOMAIN
    templatepath = os.path.join(os.path.dirname(__file__), 'templates')
    requestdata = unpackSAMLRequest(self, request)
    age = requestdata['requestage']
    if (age < 0) or (age > 590): # is our SAMLRequest old or invalid?
      self.redirect('https://mail.google.com/a/' + domain)
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
      'domain': settings.GAPPS_DOMAIN,
      
      'issueinstant': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
      'authninstant': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
      'acsurl': requestdata['acsurl'],
      'providername': requestdata['providername'],
      'requestid': requestdata['requestid'],
      'notbefore': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(time.time()) - (5 * 60))),  # 5 minutes ago
      'notafter': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(time.time()) + (10 * 60)))  # 10 minutes from now
      }
    responsepath = os.path.join(templatepath, 'response.xml')
    #response = template.render(responsepath, template_values)
    digestpath = os.path.join(templatepath, 'digest.xml')
    digestPart = template.render(digestpath, template_values)
    digestPart = digestPart[0:(len(digestPart) - 2)] # template adds \n\n at end of string, remove it
    digestSha1 = hashlib.sha1(digestPart)
    digest = b64encode(digestSha1.digest())
    template_values.update({'digest': digest})
    sipath = os.path.join(templatepath, 'response-signature-signedinfo.xml')
    signedInfo = template.render(sipath, template_values)
    signedInfo = signedInfo[0:(len(signedInfo) - 1)] # get rid of last newline
    key = gdata.tlslite.utils.keyfactory.parsePEMKey(open('privkey.pem').read(), private=True)
    signvalue = b64encode(key.hashAndSign(gdata.tlslite.utils.compat.stringToBytes(signedInfo)))      
    keyinfo = key.write()
    modulus = keyinfo[keyinfo.find('<n>')+3:keyinfo.find('</n>')]
    exponent = keyinfo[keyinfo.find('<e>')+3:keyinfo.find('</e>')]
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