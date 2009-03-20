from base64 import b64decode
from zlib import decompress
from xml.dom import minidom
import time

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