from google.appengine.ext import db
from google.appengine.api import memcache

class Filestore(db.Model):
  file_name = db.StringProperty(multiline=False)
  file_type = db.StringProperty(multiline=False)
  file_data = db.BlobProperty()

def delFile(file_name):
  retrievefiles = Filestore.gql("WHERE file_name = :1 LIMIT 1", file_name)
  for retrievefile in retrievefiles:
    retrievefile.delete()

def getFile(file_name):
  retrievefiles = Filestore.gql("WHERE file_name = :1 LIMIT 1", file_name)
  file = {}
  for retrievefile in retrievefiles:
    file['file_type'] = retrievefile.file_type
    file['file_data'] = retrievefile.file_data
  return file

def getFileList():
  return db.GqlQuery('SELECT * FROM Filestore ORDER BY file_name')

def setFile(file_name, file_type, file_data):
  file = db.GqlQuery('SELECT * FROM Filestore WHERE file_name = :1', file_name).get()
  try:
    if file.file_data == file_data and file.filefile_type == file_type:
      return
    file.file_name = file_name
    file.file_type = file_type
    file.file_data = file_data
  except AttributeError:
    file = Filestore()
    file.file_name = file_name
    file.file_type = file_type
    file.file_data = file_data
  file.put()
