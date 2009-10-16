from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
import wsgiref.handlers
import gdata.alt.appengine
import os
import gdata.apps.service
import ds_settings
import utils
import time
from random import randint
import ds_templates
import gdata.tlslite.utils.keyfactory
from base64 import b64encode
import filestore

class ShowLogin(webapp.RequestHandler):
  def get(self):
    domain = os.environ['AUTH_DOMAIN'] 
    if self.request.get('SAMLRequest') == '':
      utils.gailRedirect(self, 'https://mail.google.com/a/' + domain)
      return
    requestdata = utils.unpackSAMLRequest(self, self.request.get('SAMLRequest'))
    age = int(requestdata['requestage'])
    if (age < 0) or (age > 590): # is our SAMLRequest old or invalid?
      utils.gailRedirect(self, 'https://mail.google.com/a/' + domain)
    template_values = {
    #we want to refresh 10 sec before SAMLRequest expires
      'refresh': int(590 - age),
      'samlrequest': self.request.get('SAMLRequest'),
      'relaystate': self.request.get('RelayState'),
      'message': self.request.get('Error'),
      'message_color': 'red',
      'domain': domain,
      'appspot_domain': os.environ['APPLICATION_ID']+'.appspot.com'
      }
    self.response.out.write(ds_templates.templateRender('login.html', template_values))

class DoLogin(webapp.RequestHandler):
  def post(self):
    becomeattempt = False
    loginvalue = str(self.request.get('username'))
    if os.environ['HTTP_REFERER']:
      orig_url = os.environ['HTTP_REFERER']
    else:
      orig_url = str(os.environ['PATH_INFO'])+'?'+str(os.environ['QUERY_STRING'])
    if orig_url.find('&Error') != -1:
      orig_url = orig_url[0:orig_url.find('&Error')]
    if loginvalue.find('+') != -1:
      username = loginvalue[0:(loginvalue.find('+'))]
      loginuser = loginvalue[(loginvalue.find('+') + 1):]
      becomeattempt = True
    else:
      username = loginvalue
    password = str(self.request.get('password'))
    domain = os.environ['AUTH_DOMAIN'] 
    apps = gdata.apps.service.AppsService(email=username+'@'+domain, domain=domain, password=password)
    gdata.alt.appengine.run_on_appengine(apps, store_tokens=True, single_user_mode=True)
    try:
      apps.ProgrammaticLogin()
    except gdata.service.BadAuthentication:
      utils.gailRedirect(self, orig_url + '&Error=Unknown%20Username%20or%20Password')
    except gdata.service.CaptchaRequired:
      utils.gailRedirect(self, orig_url + '&Error=Your%20account%20is%20locked.%20%3Ca%20href%3D%22https%3A//www.google.com/a/'+domain+'/UnlockCaptcha%22%3EClick%20here%20to%20unlock%20it.%3C/a%3E')
    except:
      utils.gailRedirect(self, orig_url + '&Error=Unknown%20Error.%20Please%20Try%20Again.')
    if becomeattempt:
      if utils.userCanBecomeUser(apps, username, loginuser):
        username = loginuser
      else:
        utils.gailRedirect(self, orig_url + '&Error=Unknown%20Username%20or%20Password')
    self.response.out.write(utils.createAutoPostResponse(self, self.request.get('SAMLRequest'), username))

class ShowPassword(webapp.RequestHandler):
  def get(self):
    template_values = {
      'domain': os.environ['AUTH_DOMAIN'],
      'message': self.request.get('Message'),
      'message_color': self.request.get('message_color'),
      'appspot_domain': os.environ['APPLICATION_ID']+'.appspot.com'
      }
    self.response.out.write(ds_templates.templateRender('password.html', template_values))

class DoPassword(webapp.RequestHandler):
  def post(self):
    domain = ds_settings.getSetting('domain') 
    if os.environ['HTTP_REFERER']:
      orig_url = os.environ['HTTP_REFERER']
      if orig_url.find('?') != -1:
        orig_url = orig_url[0:orig_url.find('?')]
    else:
      orig_url = '/password'
    username = str(self.request.get('username'))
    cpassword = str(self.request.get('cpassword'))
    npassword1 = str(self.request.get('npassword1'))
    npassword2 = str(self.request.get('npassword2'))
    if npassword1 != npassword2:
      utils.gailRedirect(self, orig_url + '?message_color=red&Message=Your%20Passwords%20Do%20Not%20Match')
    if len(npassword1) < 6:
      utils.gailRedirect(self, orig_url + '?message_color=red&Message=Your%20New%20Password%20Is%20To%20Short')
    apps = gdata.apps.service.AppsService(email=username+'@'+domain, domain=domain, password=cpassword)
    gdata.alt.appengine.run_on_appengine(apps, store_tokens=True, single_user_mode=True)
    try:
      apps.ProgrammaticLogin()
    except gdata.service.BadAuthentication:
      utils.gailRedirect(self, orig_url + '?message_color=red&Message=Unknown%20Username%20or%20Password')
    except gdata.service.CaptchaRequired:
      utils.gailRedirect(self, orig_url + '?message_color=red&Message=Your%20account%20is%20locked.%20%3Ca%20href%3D%22https%3A//www.google.com/a/'+domain+'/UnlockCaptcha%22%3EClick%20here%20to%20unlock%20it.%3C/a%3E')
    except:
      utils.gailRedirect(self, orig_url + '?message_color=red&Message=Unknown%20Error%20Confirming%20Password')
    apps2 = gdata.apps.service.AppsService(email=ds_settings.getSetting('adminuser')+'@'+domain, domain=domain, password=ds_settings.getSetting('adminpass'))
    gdata.alt.appengine.run_on_appengine(apps2, store_tokens=True, single_user_mode=True)
    try:
      apps2.ProgrammaticLogin()
    except:
      utils.gailRedirect(self, orig_url + '?message_color=red&Message=Unknown%20Error%20Changing%20Password.%20Please%20Report%This%To%Your%Administrator')
    user = apps2.RetrieveUser(username)
    user.login.password = npassword1
    try:
      apps2.UpdateUser(username, user)
    except gdata.apps.service.AppsForYourDomainException , e:
      if e[0]['body'].find('InvalidPassword'):
        utils.gailRedirect(self, orig_url + '?message_color=red&Message=Your%20New%20Password%20Is%20Invalid.%20Try%20A%20Longer%20Password.')
      else:
        utils.gailRedirect(self, orig_url + '?message_color=red&Message=Unknown%20Error%20Attempting%20To%20Change%20Password.%20Please%20Report%20This%20To%20Your%20Administrator')
    utils.gailRedirect(self, orig_url + '?message_color=green&Message=Your%20password%20was%20changed%20successfully.')

class DoGailAdmin(webapp.RequestHandler):
  def get(self):
    template_values = {}
    template_values['appspot_domain'] = os.environ['APPLICATION_ID']+'.appspot.com'
    template_values['domain'] = os.environ['AUTH_DOMAIN'] 
    template_values['adminuser'] = ds_settings.getSetting('adminuser')
    template_values['adminsbecomeusers'] = ds_settings.getSetting('adminsbecomeusers')
    template_values['usersbecomeusers'] = ds_settings.getSetting('usersbecomeusers')
    template_values['privkey_ver'] = ds_settings.getSetting('privkey_ver')
    template_values['adminpass'] = '*****'
    gailpubkey = utils.getPubkey(self, ds_settings.getSetting('privkey'))
    googlepubkey = utils.GetGooglePubKey(self)
    if googlepubkey == 'failed':
      template_values['keymatch'] = 'Login to check failed'
    elif gailpubkey == googlepubkey:
      template_values['keymatch'] = 'Yes'
    else:
      template_values['keymatch'] = 'No'
    self.response.out.write(ds_templates.templateRender('gailadmin.html', template_values))
  def post(self):
    for name in self.request.arguments():
      if name == 'adminpass':
        if len(self.request.get(name)) < 6:
          continue;
      if name == 'Save':
        continue;
      value = self.request.get(name)
      ds_settings.setSetting(name, value)
    utils.gailRedirect(self, '/gailadmin')

class DoPrivKey(webapp.RequestHandler):
  def get(self):
    privkey = utils.generatePrivkey(self)
    ds_settings.setSetting('privkey', privkey)
    privkey_ver = time.strftime('%y-%m-%d-%H-%M-%S')
    ds_settings.setSetting('privkey_ver', privkey_ver)  
    utils.gailRedirect(self, '/gailadmin')

class DoPubKey(webapp.RequestHandler):
  def get(self):
    privkey = ds_settings.getSetting('privkey')
    privkey_ver = ds_settings.getSetting('privkey_ver')
    pubkey = utils.getPubkey(self, privkey)
    self.response.headers['Content-Type'] = 'application/x-x509-user-cert'
    self.response.headers['Content-Disposition'] = 'attachment; filename="'+privkey_ver+'.der"'
    self.response.out.write(pubkey)

class DoUpdateGoogleSSO(webapp.RequestHandler):
  def get(self):
    privkey = ds_settings.getSetting('privkey')
    pubkey = utils.getPubkey(self, privkey)
    gailUrl = 'https://'+os.environ['APPLICATION_ID']+'.appspot.com/'
    utils.putGoogleSSO(gailUrl, pubkey)
    utils.gailRedirect(self, '/gailadmin')

class DoEditTemplates(webapp.RequestHandler):
  def get(self):
    template_values = {}
    template_values['appspot_domain'] = os.environ['APPLICATION_ID']+'.appspot.com'
    template_values['domain'] = os.environ['AUTH_DOMAIN']
    template_values['login_template_data'] = ds_templates.getTemplate('login.html')
    template_values['password_template_data'] = ds_templates.getTemplate('password.html')
    template_values['filelist'] = filestore.getFileList()
    self.response.out.write(ds_templates.templateRender('edit-templates.html', template_values))
  def post(self):
    login_template_data = str(self.request.get('login-html'))
    if str(self.request.get('resetloginpage')) == 'on':
      login_template_data = open('templates/login.html').read()
    ds_templates.updateTemplate('login.html', login_template_data)
    password_template_data = str(self.request.get('password-html'))
    if str(self.request.get('resetpasswordpage')) == 'on':
      password_template_data = open('templates/password.html').read()
    ds_templates.updateTemplate('password.html', password_template_data)
    utils.gailRedirect(self, '/edittemplates')

class GetDynamicFile(webapp.RequestHandler):
  def get(self):
    file_name = str(self.request.get('file'))
    if len(file_name) > 12:
      return
    allowedchars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_'
    for i in file_name[:]:
      if allowedchars.find(i) == -1:
        return
    file = filestore.getFile(file_name)
    self.response.headers['Content-Type'] = file['file_type']
    self.response.out.write(file['file_data'])

class PutDynamicFile(webapp.RequestHandler):
  def post(self):
    file_data = self.request.get('file')
    file_name = self.request.body_file.vars['file'].filename
    if len(file_name) > 12:
      return
    allowedchars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_'
    for i in file_name[:]:
      if allowedchars.find(i) == -1:
        return
    file_type = self.request.body_file.vars['file'].headers['content-type']
    filestore.setFile(file_name, file_type, file_data)
    self.response.out.write('Hello')
    utils.gailRedirect(self, '/edittemplates')
 
application = webapp.WSGIApplication([('/password', ShowPassword),
                                     ('/dopassword', DoPassword),
                                     ('/dologin', DoLogin),
                                     ('/', ShowLogin),
                                     ('/gailadmin', DoGailAdmin),
                                     ('/newprivkey', DoPrivKey),
                                     ('/getpubkey', DoPubKey),
                                     ('/updategooglesso', DoUpdateGoogleSSO),
                                     ('/edittemplates', DoEditTemplates),
                                     ('/dfile', GetDynamicFile),
                                     ('/upload-dfile', PutDynamicFile)],
                                     debug=True)

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
