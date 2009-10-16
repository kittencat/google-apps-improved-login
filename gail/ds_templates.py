import os
from google.appengine.ext import db
from google.appengine.api import memcache

try:
  from django import v0_96
except ImportError:
  pass
import django
import django.conf
try:
  django.conf.settings.configure(
    DEBUG=False,
    TEMPLATE_DEBUG=False,
    TEMPLATE_LOADERS=(
      'django.template.loaders.filesystem.load_template_source',
    ),
  )
except (EnvironmentError, RuntimeError):
  pass
from django.template import Context, Template

class Templates(db.Model):
  template_name = db.StringProperty(multiline=False)
  template_data = db.TextProperty()

def getTemplate(template_name):
  #template_data = memcache.get(template_name)
  template_data = None
  if template_data is None:
    retrievetemplates = Templates.gql("WHERE template_name = :1", template_name)
    for retrievetemplate in retrievetemplates:
      template_data = retrievetemplate.template_data
    if template_data is None:
      template_data = open('templates/'+template_name).read()
      template_put = Templates()
      template_put.template_name = template_name
      template_put.template_data = template_data
      template_put.put()
    memcache.set(template_name, template_data)
  return template_data

def templateRender(template_name, template_values):
  template_data = getTemplate(template_name)
  t = Template(template_data)
  c = Context(template_values)
  return t.render(c)

def updateTemplate(template_name, template_data):
  template = db.GqlQuery('SELECT * FROM Templates WHERE template_name = :1', template_name).get()
  try:
    if template_data == template.template_data:
      return
    template.template_data = template_data
  except AttributeError:
    template = Templates()
    template.template_name = template_name
    template.template_data = template_data
  template.put()
  memcache.set(template_name, template_data)
