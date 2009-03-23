from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
import gdata.alt.appengine
import os
import random
import base64
import hashlib
import zlib
import time
import binascii
from xml.dom import minidom
import gdata.apps.service
import urllib
import settings
import utils

class ShowLogin(webapp.RequestHandler):
  def get(self):
    domain = settings.GAPPS_DOMAIN
    if self.request.get('SAMLRequest') == '':
      self.redirect('https://mail.google.com/a/' + domain)
      return
    SAMLRequest = self.request.get('SAMLRequest')
    age = utils.getSAMLRequestAge(SAMLRequest)
    if (age < 0) or (age > 590): # is our SAMLRequest old or invalid?
      self.redirect('https://mail.google.com/a/' + domain)
    template_values = {
    #we want to refresh 10 sec before SAMLRequest expires
      'refresh': int(590 - age),
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
    becomeattempt = False
    loginvalue = str(self.request.get('username'))
    if loginvalue.find('+') != -1:
      username = loginvalue[0:(loginvalue.find('+'))]
      loginuser = loginvalue[(loginvalue.find('+') + 1):]
      becomeattempt = True
    else:
      username = loginvalue
    password = str(self.request.get('password'))
    domain = settings.GAPPS_DOMAIN
    apps = gdata.apps.service.AppsService(email=username+'@'+domain, domain=domain, password=password)
    gdata.alt.appengine.run_on_appengine(apps, store_tokens=True, single_user_mode=True)
    try:
      apps.ProgrammaticLogin()
    except gdata.service.BadAuthentication:
      self.redirect('/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=Unknown%20Username%20or%20Password')
    if becomeattempt:
      if utils.userCanBecomeUser(apps, username, loginuser):
        username = loginuser
      else:
        self.redirect('/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=Unknown%20Username%20or%20Password')
    autopostpath = os.path.join(templatepath, 'autopost.html')
    autopost_values = {
      'acsurl': xmldoc.firstChild.attributes['AssertionConsumerServiceURL'].value,
      'signedresponse': base64.b64encode(signedresponse),
      'relaystate': self.request.get('RelayState') # template takes care of escaping for IE
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
