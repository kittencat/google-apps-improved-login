from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
import gdata.alt.appengine
import os
import gdata.apps.service
import urllib
import settings
import utils
from google.appengine.ext.webapp import template

class ShowLogin(webapp.RequestHandler):
  def get(self):
    domain = settings.GAPPS_DOMAIN
    if self.request.get('SAMLRequest') == '':
      self.redirect('https://mail.google.com/a/' + domain)
      return
    requestdata = utils.unpackSAMLRequest(self, self.request.get('SAMLRequest'))
    age = requestdata['requestage']
    if (age < 0) or (age > 590): # is our SAMLRequest old or invalid?
      self.redirect('https://mail.google.com/a/' + domain)
    template_values = {
    #we want to refresh 10 sec before SAMLRequest expires
      'refresh': int(590 - age),
      'samlrequest': self.request.get('SAMLRequest'),
      'relaystate': self.request.get('RelayState'),
      'error': self.request.get('Error'),
      'domain': domain,
      'appspot_domain': os.environ['APPLICATION_ID']+'.appspot.com'
      }
    path = os.path.join(os.path.dirname(__file__), 'templates')
    path = os.path.join(path, 'login.html')
    self.response.out.write(template.render(path, template_values))

class DoLogin(webapp.RequestHandler):
  def post(self):
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
    orig_domain = os.environ['HTTP_REFERER']
    apps = gdata.apps.service.AppsService(email=username+'@'+domain, domain=domain, password=password)
    gdata.alt.appengine.run_on_appengine(apps, store_tokens=True, single_user_mode=True)
    try:
      apps.ProgrammaticLogin()
    except gdata.service.BadAuthentication:
      self.redirect(orig_domain + '/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=Unknown%20Username%20or%20Password')
    except gdata.service.CaptchaRequired:
      self.redirect(orig_domain + '/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=Your%20account%20is%20locked.%20%3Ca%20href%3D%22https%3A//www.google.com/a/'+domain+'/UnlockCaptcha%22%3EClick%20here%20to%20unlock%20it.%3C/a%3E')
    if becomeattempt:
      if utils.userCanBecomeUser(apps, username, loginuser):
        username = loginuser
      else:
        self.redirect(orig_domain + '/?SAMLRequest='+urllib.quote(self.request.get('SAMLRequest'))+'&RelayState='+urllib.quote(self.request.get('RelayState'))+'&Error=Unknown%20Username%20or%20Password')
    self.response.out.write(utils.createAutoPostResponse(self, self.request.get('SAMLRequest'), username))

class ShowPassword(webapp.RequestHandler):
  def get(self):
    templatepath = os.path.join(os.path.dirname(__file__), 'templates')
    passwordpath = os.path.join(templatepath, 'login.html')
    template_values = {
      'domain': settings.GAPPS_DOMAIN,
      'message': self.request.get('Message'),
      'color': self.request.get('color'),
      'appspot_domain': os.environ['APPLICATION_ID']+'.appspot.com'
      }
    self.response.out.write(template.render(passwordpath, template_values))

class DoPassword(webapp.RequestHandler):
  def post(self):
    domain = settings.GAPPS_DOMAIN
    orig_domain = os.environ['HTTP_REFERER']
    username = str(self.request.get('username'))
    cpassword = str(self.request.get('cpassword'))
    npassword1 = str(self.request.get('npassword1'))
    npassword2 = str(self.request.get('npassword2'))
    if npassword1 != npassword2:
      self.redirect(orig_domain + '/password?color=red&Message=Your%20Passwords%20Do%20Not%20Match')
    if len(npassword1) < 6:
      self.redirect(orig_domain + '/password?color=red&Message=Your%20New%20Password%20Is%20To%20Short')
    apps = gdata.apps.service.AppsService(email=username+'@'+domain, domain=domain, password=cpassword)
    gdata.alt.appengine.run_on_appengine(apps, store_tokens=True, single_user_mode=True)
    try:
      apps.ProgrammaticLogin()
    except gdata.service.BadAuthentication:
      self.redirect(orig_domain + '/password?color=red&Message=Unknown%20Username%20or%20Password')
    except gdata.service.CaptchaRequired:
      self.redirect(orig_domain + '/password?color=red&Message=Your%20account%20is%20locked.%20%3Ca%20href%3D%22https%3A//www.google.com/a/'+domain+'/UnlockCaptcha%22%3EClick%20here%20to%20unlock%20it.%3C/a%3E')
    except:
      self.redirect(orig_domain + '/password?color=red&Message=Unknown%20Error%20Confirming%20Password')
    apps2 = gdata.apps.service.AppService(email=settings.ADMIN_USER+'@'+domain, domain=domain, password=settings.ADMIN_PASS)
    try:
      apps2.ProgrammaticLogin()
    except:
      self.redirect(orig_domain + '/password?color=red&Message=Unknown%20Error%20Changing%20Password.%20Please%20Report%This%To%Your%Administrator')
    user = apps2.RetrieveUser(username)
    user.login.password = npassword1
    try:
      apps2.UpdateUser(username, user)
    except gdata.apps.service.AppsForYourDomainException , e:
      if e[0]['body'].find('InvalidPassword'):
        self.redirect(orig_domain + '/password?color=red&Message=Your%20New%20Password%20Is%20Invalid.%20Try%20A%20Longer%20Password.')
      else:
        self.redirect(orig_domain + '/password?color=red&Message=Unknown%20Error%20Attempting%20To%20Change%20Password.%20Please%20Report%20This%20To%20Your%20Administrator')
    self.redirect(orig_domain + '/password?color=green&Message=Your%20password%20was%20changed%20successfully.')
    
application = webapp.WSGIApplication(
                                     [('/password', ShowPassword),
                                      ('/dopassword', DoPassword),
                                      ('/dologin', DoLogin),
                                      ('/login', ShowLogin)],
                                     debug=False)

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
