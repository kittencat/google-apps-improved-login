from base64 import b64decode
from zlib import decompress
from xml.dom import minidom
import time
import re
import settings
import gdata.alt.appengine
import gdata.apps.service
import gdata.apps.groups.service

def getSAMLRequestAge (samlRequest):
  #Takes a b64 encoded, zlib compressed samlRequest string, unpack and returns
  #the request's age in seconds
  
  request = b64decode(samlRequest)
  request = decompress(request, -8)
  xmldoc = minidom.parseString(request)
  requestdateString = xmldoc.firstChild.attributes['IssueInstant'].value + ' UTC' # Google doesn't specify but it's UTC
  requestdate = time.mktime(time.strptime(requestdateString, "%Y-%m-%dT%H:%M:%SZ %Z"))
  now = time.mktime(time.gmtime())
  return now - requestdate

def userCanBecomeUser (apps, username, loginname):
  # Takes a apps resource, username and loginname.  Checks to see if username has rights
  # to login as loginname using ADMINS_BECOME_USER or USERS_BECOME_USERS.  Returns True/False.
  
  if settings.ADMINS.BECOME_USER:
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
        elif groupsadmin.IsMember(loginname, group['groupId'][0:(group['groupId'].find('@'))]) or groupsadmin.IsMember('*', group['groupId'][0:(group['groupId'].find('@'))]):
          canBecome = True
          break
    return canBecome
  return False