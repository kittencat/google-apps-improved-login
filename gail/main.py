from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
import gdata.alt.appengine
import os
from google.appengine.ext.webapp import template
import random
import base64
import hashlib
import zlib
import time
import binascii
from xml.dom import minidom
from gdata.tlslite.utils.RSAKey import RSAKey
from privkey import key
import gdata.tlslite.utils.compat
import gdata.apps.service
import urllib
import settings
import utils

class ShowLogin(webapp.RequestHandler):
  def get(self):
    domain = settings.GAPPS_DOMAIN
    if self.request.get('SAMLRequest') == None:
      self.redirect('https://mail.google.com/a/' + domain)
    SAMLRequest = self.request.get('SAMLRequest')
    age = utils.getSAMLRequestAge(SAMLRequest)
    if (age < 0) or (age > 590): # is our SAMLRequest old or invalid?
      self.redirect('https://mail.google.com/a/' + domain)
    template_values = {
      'samlrequest': self.request.get('SAMLRequest'),
      'relaystate': self.request.get('RelayState'),
      'error': self.request.get('Error'),
      'domain': domain
      }
    path = os.path.join(os.path.dirname(__file__), 'templates')
    path = os.path.join(path, 'login.html')
    self.response.out.write(template.render(path, template_values))

class DoLogin(webapp.RequestHandler):
  def post(self):
    templatepath = os.path.join(os.path.dirname(__file__), 'templates')
    adminattempt = False
    loginvalue = str(self.request.get('username'))
    if settings.ADMINS_BECOME_USER and loginvalue.find('+') != -1:
      username = loginvalue[0:(loginvalue.find('+'))]
      loginuser = loginvalue[(loginvalue.find('+') + 1):]
      adminattempt = True
    else:
      username = loginvalue
    password = self.request.get('password')
    domain = settings.GAPPS_DOMAIN
    apps = gdata.apps.service.AppsService(email=username+'@'+domain, domain=domain, password=password)
    gdata.alt.appengine.run_on_appengine(apps, store_tokens=True, single_user_mode=True)
    try:
      apps.ProgrammaticLogin()
    except gdata.service.BadAuthentication:
      self.redirect('/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=Unknown%20Username%20or%20Password')
    #Verify admin status by looking self up...
    if adminattempt:
      try:
        LookupUser = apps.RetrieveUser(username)
      except gdata.apps.service.AppsForYourDomainException , e:
        self.redirect('/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=You%20Are%20Not%20An%20Admin.')
      username = loginuser
    if self.request.get('SAMLRequest') == '' or self.request.get('SAMLRequest') == None:
      self.redirect('/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState')))
    else:
      ranchars = 'abcdefghijklmnop'
      responseid = ''
      assertid = ''
      for i in range(1, 40):
        responseid += ranchars[random.randint(0,15)]
        assertid += ranchars[random.randint(0,15)]
      request = self.request.get('SAMLRequest')
      request = base64.b64decode(request)
      request = zlib.decompress(request, -8)
      xmldoc = minidom.parseString(request)
      template_values = {
        'assertid': assertid,
        'responseid': responseid,
        'username': username,
        'domain': domain,
        'issueinstant': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'authninstant': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'acsurl': xmldoc.firstChild.attributes['AssertionConsumerServiceURL'].value,
        'providername': xmldoc.firstChild.attributes['ProviderName'].value,
        'requestid': xmldoc.firstChild.attributes['ID'].value,
        'notbefore': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(time.time()) - (5 * 60))),  # 5 minutes ago
        'notafter': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(time.time()) + (10 * 60)))  # 10 minutes from now
        }
      responsepath = os.path.join(templatepath, 'response.xml')
      #response = template.render(responsepath, template_values)
      digestpath = os.path.join(templatepath, 'digest.xml')
      digestPart = template.render(digestpath, template_values)
      digestPart = digestPart[0:(len(digestPart) - 2)] # template adds \n\n at end of string, remove it
      digestSha1 = hashlib.sha1(digestPart)
      digest = base64.b64encode(digestSha1.digest())
      template_values.update({'digest': digest})
      sipath = os.path.join(templatepath, 'response-signature-signedinfo.xml')
      signedInfo = template.render(sipath, template_values)
      signedInfo = signedInfo[0:(len(signedInfo) - 1)] # get rid of last newline
      signvalue = base64.b64encode(key.hashAndSign(gdata.tlslite.utils.compat.stringToBytes(signedInfo)))      
      keyinfo = key.write()
      modulus = keyinfo[keyinfo.find('<n>')+3:keyinfo.find('</n>')]
      exponent = keyinfo[keyinfo.find('<e>')+3:keyinfo.find('</e>')]
      template_values.update({'signvalue': signvalue, 'modulus': modulus, 'exponent': exponent})
      responsepath = os.path.join(templatepath, 'response.xml')
      signedresponse = template.render(responsepath, template_values) 
      autopostpath = os.path.join(templatepath, 'autopost.html')
      autopost_values = {
        'acsurl': xmldoc.firstChild.attributes['AssertionConsumerServiceURL'].value,
        'signedresponse': base64.b64encode(signedresponse),
        'relaystate': self.request.get('RelayState')
        }
      self.response.out.write(template.render(autopostpath, autopost_values))
      #self.response.out.write("<html><body>\n\nResponse:\n\n"+response+"\n\nDigest:\n\n"+digest+"\n\nDigestPart:\n\n"+digestPart+"\n\nSigned Response:\n\n"+signedresponse+"\n\n</body></html>")

application = webapp.WSGIApplication(
                                     [('/dologin', DoLogin),
                                      ('/', ShowLogin)],
                                     debug=True)

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
