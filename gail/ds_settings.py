from google.appengine.ext import db
from google.appengine.api import memcache

class Setting(db.Model):
  name = db.StringProperty(multiline=False)
  value = db.TextProperty()

def getSetting(name):
  #memcache.flush_all()
  #value = memcache.get(name)
  value = None
  if value == None:
    retrievesettings = Setting.gql("WHERE name = :1 LIMIT 1", name)
    for retrievesetting in retrievesettings:
      value = retrievesetting.value
    if value == None:  #nothing in datastore, pull values from settings.py
      import settings
      if name == 'adminsbecomeusers':
        value = str(settings.ADMINS_BECOME_USER)
      elif name == 'usersbecomeusers':
        value = str(settings.USERS_BECOME_USERS)
      elif name == 'adminuser':
        value = settings.ADMIN_USER
      elif name == 'adminpass':
        value = settings.ADMIN_PASS.encode('rot13')
      elif name == 'privkey':
        try:
          value = open('privkey.pem').read()
        except IOError:
          pass
      elif name == 'privkey_ver':
        value = 'pre GAIL 0.5 key'
      setSetting(name, value)
    elif name == 'adminpass':
      value = value.encode('rot13')
    memcache.add(name, value)
  return value

def setSetting(name, value):
  if name == 'adminpass':
    value = value.encode('rot13')
  setting = db.GqlQuery('SELECT * FROM Setting WHERE name = :1', name).get()
  try:
    if value == setting.value:
      return
    setting.name = name
    setting.value = value
  except AttributeError:
    setting = Setting()
    setting.name = name
    setting.value = value 
  setting.put()
  memcache.set(name, value)
