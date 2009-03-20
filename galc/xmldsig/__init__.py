#!/usr/bin/python
#
# Copyright (C) 2007 SIOS Technology, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains objects used with xmldsig."""

__author__ = 'tmatsuo@sios.com (Takashi MATSUO)'

"""Contains classes representing xmldsig elements.

  Module objective: provide data classes for xmldsig constructs. These
  classes hide the XML-ness of Saml and provide a set of native Python
  classes to interact with.

  Classes in this module inherits saml.SamlBase now.

"""

try:
  from xml.etree import cElementTree as ElementTree
except ImportError:
  try:
    import cElementTree as ElementTree
  except ImportError:
    from elementtree import ElementTree
import saml2

DS_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'
DS_TEMPLATE = '{http://www.w3.org/2000/09/xmldsig#}%s'

ENCODING_BASE64 = 'http://www.w3.org/2000/09/xmldsig#base64'
DIGEST_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
ALG_EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
SIG_DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
SIG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
MAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'

C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
C14N_WITH_C = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments'

TRANSFORM_XSLT = 'http://www.w3.org/TR/1999/REC-xslt-19991116'
TRANSFORM_XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116'
TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'


class DsBase(saml2.SamlBase):
  """The ds:DsBase element"""

  _children = {}
  _attributes = {}

class Object(DsBase):
  """The ds:Object element"""

  _tag = 'Object'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Id'] = 'id'
  _attributes['MimeType'] = 'mime_type'
  _attributes['Encoding'] = 'encoding'

  def __init__(self, id=None, mime_type=None, encoding=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for Object

    Args:
      id: Id attribute
      mime_type: MimeType attribute
      encoding: Encoding attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.id = id
    self.mime_type = mime_type
    self.encoding = encoding
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def ObjectFromString(xml_string):
  return saml2.CreateClassFromXMLString(Object, xml_string)

class MgmtData(DsBase):
  """The ds:MgmtData element"""

  _tag = 'MgmtData'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def MgmtDataFromString(xml_string):
  return saml2.CreateClassFromXMLString(MgmtData, xml_string)


class SPKISexp(DsBase):
  """The ds:SPKISexp element"""

  _tag = 'SPKISexp'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def SPKISexpFromString(xml_string):
  return saml2.CreateClassFromXMLString(SPKISexp, xml_string)


class SPKIData(DsBase):
  """The ds:SPKIData element"""

  _tag = 'SPKIData'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _children['{%s}SPKISexp' % DS_NAMESPACE] = ('spki_sexp', [SPKISexp])

  def __init__(self, spki_sexp=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for SPKIData

    Args:
      spki_sexp: SPKISexp elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.spki_sexp = spki_sexp or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def SPKIDataFromString(xml_string):
  return saml2.CreateClassFromXMLString(SPKIData, xml_string)


class PGPKeyID(DsBase):
  """The ds:PGPKeyID element"""

  _tag = 'PGPKeyID'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def PGPKeyIDFromString(xml_string):
  return saml2.CreateClassFromXMLString(PGPKeyID, xml_string)


class PGPKeyPacket(DsBase):
  """The ds:PGPKeyPacket element"""

  _tag = 'PGPKeyPacket'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def PGPKeyPacketFromString(xml_string):
  return saml2.CreateClassFromXMLString(PGPKeyPacket, xml_string)


class PGPData(DsBase):
  """The ds:PGPData element"""

  _tag = 'PGPData'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _children['{%s}PGPKeyID' % DS_NAMESPACE] = ('pgp_key_id', PGPKeyID)
  _children['{%s}PGPKeyPacket' % DS_NAMESPACE] = (
    'pgp_key_packet', PGPKeyPacket)
  _child_order = ['pgp_key_id', 'pgp_key_packet']

  def __init__(self, pgp_key_id=None, pgp_key_packet=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for PGPKeyINfo

    Args:
      pgp_key_id: PGPKeyID element
      pgp_key_packet: PGPKeyPacket element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.pgp_key_id = pgp_key_id
    self.pgp_key_packet = pgp_key_packet
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}


def PGPDataFromString(xml_string):
  return saml2.CreateClassFromXMLString(PGPData, xml_string)


class X509IssuerName(DsBase):
  """The ds:X509IssuerName element"""

  _tag = 'X509IssuerName'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def X509IssuerNameFromString(xml_string):
  return saml2.CreateClassFromXMLString(X509IssuerName, xml_string)


class X509IssuerNumber(DsBase):
  """The ds:X509IssuerNumber element"""

  _tag = 'X509IssuerNumber'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def X509IssuerNumberFromString(xml_string):
  return saml2.CreateClassFromXMLString(X509IssuerNumber, xml_string)


class X509IssuerSerial(DsBase):
  """The ds:X509IssuerSerial element"""

  _tag = 'X509IssuerSerial'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _children['{%s}X509IssuerName' % DS_NAMESPACE] = (
    'x509_issuer_name', X509IssuerName)
  _children['{%s}X509IssuerNumber' % DS_NAMESPACE] = (
    'x509_issuer_number', X509IssuerNumber)
  _child_order = ['x509_issuer_name', 'x509_issuer_number']

  def __init__(self, x509_issuer_name=None, x509_issuer_number=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for X509IssuerSerial

    Args:
      x509_issuer_name: X509IssuerName
      x509_issuer_number: X509IssuerNumber
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.x509_issuer_name = x509_issuer_name
    self.x509_issuer_number = x509_issuer_number
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}


def X509IssuerSerialFromString(xml_string):
  return saml2.CreateClassFromXMLString(X509IssuerSerial, xml_string)


class X509SKI(DsBase):
  """The ds:X509SKI element"""

  _tag = 'X509SKI'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def X509SKIFromString(xml_string):
  return saml2.CreateClassFromXMLString(X509SKI, xml_string)


class X509SubjectName(DsBase):
  """The ds:X509SubjectName element"""

  _tag = 'X509SubjectName'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def X509SubjectNameFromString(xml_string):
  return saml2.CreateClassFromXMLString(X509SubjectName, xml_string)


class X509Certificate(DsBase):
  """The ds:X509Certificate element"""

  _tag = 'X509Certificate'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def X509CertificateFromString(xml_string):
  return saml2.CreateClassFromXMLString(X509Certificate, xml_string)


class X509CRL(DsBase):
  """The ds:X509CRL element"""

  _tag = 'X509CRL'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def X509CRLFromString(xml_string):
  return saml2.CreateClassFromXMLString(X509CRL, xml_string)


class X509Data(DsBase):
  """The ds:X509Data element"""

  _tag = 'X509Data'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _children['{%s}X509IssuerSerial' % DS_NAMESPACE] = (
    'x509_issuer_serial', [X509IssuerSerial])
  _children['{%s}X509SKI' % DS_NAMESPACE] = ('x509_ski', [X509SKI])
  _children['{%s}X509SubjectName' % DS_NAMESPACE] = (
    'x509_subject_name', [X509SubjectName])
  _children['{%s}X509Certificate' % DS_NAMESPACE] = (
    'x509_certificate', [X509Certificate])
  _children['{%s}X509CRL' % DS_NAMESPACE] = ('x509_crl', [X509CRL])
  _child_order = ['x509_issuer_serial', 'x509_ski', 'x509_subject_name',
                  'x509_certificate', 'x509_crl']

  def __init__(self, x509_issuer_serial=None, x509_ski=None,
               x509_subject_name=None, x509_certificate=None, x509_crl=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for X509Data

    Args:
      x509_issuer_serial: X509IssuerSerial element
      x509_ski: X509SKI element
      x509_subject_name: X509SubjectName element
      x509_certificate: X509Certificate element
      x509_crl: X509CRL element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.x509_issuer_serial = x509_issuer_serial or []
    self.x509_ski = x509_ski or []
    self.x509_subject_name = x509_subject_name or []
    self.x509_certificate = x509_certificate or []
    self.x509_crl = x509_crl or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}


def X509DataFromString(xml_string):
  return saml2.CreateClassFromXMLString(X509Data, xml_string)


class XPath(DsBase):
  """The ds:XPath element"""

  _tag = 'XPath'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def XPathFromString(xml_string):
  return saml2.CreateClassFromXMLString(XPath, xml_string)


class Transform(DsBase):
  """The ds:Transform element"""

  _tag = 'Transform'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Algorithm'] = 'algorithm'
  _children['{%s}XPath' % DS_NAMESPACE] = ('xpath', [XPath])

  def __init__(self, xpath=None, algorithm=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for Transform

    Args:
      xpath: XPath elements
      algorithm: Algorithm attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.xpath = xpath or []
    self.algorithm = algorithm
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}


def TransformFromString(xml_string):
  return saml2.CreateClassFromXMLString(Transform, xml_string)


class Transforms(DsBase):
  """The ds:Transforms element"""

  _tag = 'Transforms'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _children['{%s}Transform' % DS_NAMESPACE] = ('transform', [Transform])

  def __init__(self, transform=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for Transforms

    Args:
      transform: Transform elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.transform = transform or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}


def TransformsFromString(xml_string):
  return saml2.CreateClassFromXMLString(Transforms, xml_string)


class RetrievalMethod(DsBase):
  """The ds:RetrievalMethod element"""

  _tag = 'RetrievalMethod'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['URI'] = 'uri'
  _attributes['Type'] = 'type'
  _children['{%s}Transforms' % DS_NAMESPACE] = ('transforms', [Transforms])

  def __init__(self, transforms=None, uri=None, type=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for RetrievalMethod

    Args:
      transforms: Transforms elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.transforms = transforms or []
    self.uri = uri
    self.type = type
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def RetrievalMethodFromString(xml_string):
  return saml2.CreateClassFromXMLString(RetrievalMethod, xml_string)


class Modulus(DsBase):
  """The ds:Modulus element"""

  _tag = 'Modulus'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def ModulusFromString(xml_string):
  return saml2.CreateClassFromXMLString(Modulus, xml_string)


class Exponent(DsBase):
  """The ds:Exponent element"""

  _tag = 'Exponent'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def ExponentFromString(xml_string):
  return saml2.CreateClassFromXMLString(Exponent, xml_string)


class RSAKeyValue(DsBase):
  """The ds:RSAKeyValue element"""

  _tag = 'RSAKeyValue'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _children['{%s}Modulus' % DS_NAMESPACE] = ('modulus', Modulus)
  _children['{%s}Exponent' % DS_NAMESPACE] = ('exponent', Exponent)
  _child_order = ['modulus', 'exponent']

  def __init__(self, modulus=None, exponent=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for RSAKeyValue

    Args:
      modulus: Modulus element
      exponent: Exponent element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.modulus = modulus
    self.exponent = exponent
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def RSAKeyValueFromString(xml_string):
  return saml2.CreateClassFromXMLString(RSAKeyValue, xml_string)


class P(DsBase):
  """The ds:P element"""

  _tag = 'P'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def PFromString(xml_string):
  return saml2.CreateClassFromXMLString(P, xml_string)


class Q(DsBase):
  """The ds:Q element"""

  _tag = 'Q'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def QFromString(xml_string):
  return saml2.CreateClassFromXMLString(Q, xml_string)


class G(DsBase):
  """The ds:G element"""

  _tag = 'G'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def GFromString(xml_string):
  return saml2.CreateClassFromXMLString(G, xml_string)


class Y(DsBase):
  """The ds:Y element"""

  _tag = 'Y'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def YFromString(xml_string):
  return saml2.CreateClassFromXMLString(Y, xml_string)


class J(DsBase):
  """The ds:J element"""

  _tag = 'J'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def JFromString(xml_string):
  return saml2.CreateClassFromXMLString(J, xml_string)


class Seed(DsBase):
  """The ds:Seed element"""

  _tag = 'Seed'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def SeedFromString(xml_string):
  return saml2.CreateClassFromXMLString(Seed, xml_string)


class PgenCounter(DsBase):
  """The ds:PgenCounter element"""

  _tag = 'PgenCounter'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def PgenCounterFromString(xml_string):
  return saml2.CreateClassFromXMLString(PgenCounter, xml_string)


class DSAKeyValue(DsBase):
  """The ds:DSAKeyValue element"""

  _tag = 'DSAKeyValue'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _children['{%s}P' % DS_NAMESPACE] = ('p', P)
  _children['{%s}Q' % DS_NAMESPACE] = ('q', Q)
  _children['{%s}G' % DS_NAMESPACE] = ('g', G)
  _children['{%s}Y' % DS_NAMESPACE] = ('y', Y)
  _children['{%s}J' % DS_NAMESPACE] = ('j', J)
  _children['{%s}Seed' % DS_NAMESPACE] = ('seed', Seed)
  _children['{%s}PgenCounter' % DS_NAMESPACE] = ('pgen_counter', PgenCounter)

  _child_order = ['p', 'q', 'g', 'y', 'j', 'seed', 'pgen_counter']

  def __init__(self, p=None, q=None, g=None, y=None, j=None, seed=None,
               pgen_counter=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for DSAKeyValue

    Args:
      p: P element
      q: Q element
      g: G element
      y: Y element
      j: J element
      seed: Seed element
      pgen_counter: PgenCounter element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.p = p
    self.q = q
    self.g = g
    self.y = y
    self.j = j
    self.seed = Seed
    self.pgen_counter = pgen_counter
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def DSAKeyValueFromString(xml_string):
  return saml2.CreateClassFromXMLString(DSAKeyValue, xml_string)


class KeyValue(DsBase):
  """The ds:KeyValue element"""

  _tag = 'KeyValue'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _children['{%s}RSAKeyValue' % DS_NAMESPACE] = ('rsa_key_value', RSAKeyValue)
  _children['{%s}DSAKeyValue' % DS_NAMESPACE] = ('dsa_key_value', DSAKeyValue)

  _child_order = ['rsa_key_value', 'dsa_key_value']

  def __init__(self, rsa_key_value=None, dsa_key_value=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for DSAKeyValue

    Args:
      rsa_key_value: RSAKeyValue element
      dsa_key_value: DSAKeyValue element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.rsa_key_value = rsa_key_value
    self.dsa_key_value = dsa_key_value
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def KeyValueFromString(xml_string):
  return saml2.CreateClassFromXMLString(KeyValue, xml_string)


class KeyName(DsBase):
  """The ds:KeyName element"""

  _tag = 'KeyName'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def KeyNameFromString(xml_string):
  return saml2.CreateClassFromXMLString(KeyName, xml_string)


class KeyInfo(DsBase):
  """The ds:KeyInfo element"""

  _tag = 'KeyInfo'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Id'] = "id"
  _children['{%s}KeyName' % DS_NAMESPACE] = ('key_name', [KeyName])
  _children['{%s}KeyValue' % DS_NAMESPACE] = ('key_value', [KeyValue])
  _children['{%s}RetrievalMethod' % DS_NAMESPACE] = (
    'retrieval_method', [RetrievalMethod])
  _children['{%s}X509Data' % DS_NAMESPACE] = ('x509_data', [X509Data])
  _children['{%s}PGPData' % DS_NAMESPACE] = ('pgp_data', [PGPData])
  _children['{%s}SPKIData' % DS_NAMESPACE] = ('spki_data', [SPKIData])
  _children['{%s}MgmtData' % DS_NAMESPACE] = ('mgmt_data', [MgmtData])

  _child_order = ['key_name', 'key_value', 'retrieval_method', 'x509_data',
                  'pgp_data', 'spki_data', 'mgmt_data']

  def __init__(self, key_name=None, key_value=None, retrieval_method=None,
               x509_data=None, pgp_data=None, spki_data=None, mgmt_data=None,
               id=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for DSAKeyValue

    Args:
      key_name: KeyName elements
      key_value: KeyValue elements
      retrieval_method: RetrievalMethod elements
      x509_data: X509Data elements
      pgp_data: PGPData elements
      spki_data: SPKIData elements
      mgmt_data: MgmtData elements
      id: Id attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.key_name = key_name or []
    self.key_value = key_value or []
    self.retrieval_method = retrieval_method or []
    self.x509_data = x509_data or []
    self.pgp_data = pgp_data or []
    self.spki_data = spki_data or []
    self.mgmt_data = mgmt_data or []
    self.id = id
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def KeyInfoFromString(xml_string):
  return saml2.CreateClassFromXMLString(KeyInfo, xml_string)


class DigestValue(DsBase):
  """The ds:DigestValue element"""

  _tag = 'DigestValue'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def DigestValueFromString(xml_string):
  return saml2.CreateClassFromXMLString(DigestValue, xml_string)


class DigestMethod(DsBase):
  """The ds:DigestMethod element"""

  _tag = 'DigestMethod'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Algorithm'] = "algorithm"

  def __init__(self, algorithm=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for DSAKeyValue

    Args:
      algorithm: Algorithm attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.algorithm = algorithm
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def DigestMethodFromString(xml_string):
  return saml2.CreateClassFromXMLString(DigestMethod, xml_string)


class Reference(DsBase):
  """The ds:Reference element"""

  _tag = 'Reference'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Id'] = "id"
  _attributes['URI'] = "uri"
  _attributes['Type'] = "type"
  _children['{%s}Transforms' % DS_NAMESPACE] = ('transforms', [Transforms])
  _children['{%s}DigestMethod' % DS_NAMESPACE] = (
    'digest_method', [DigestMethod])
  _children['{%s}DigestValue' % DS_NAMESPACE] = ('digest_value', [DigestValue])
  _child_order = ['transforms', 'digest_method', 'digest_value']

  def __init__(self, id=None, uri=None, type=None, transforms=None,
               digest_method=None, digest_value=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for Reference

    Args:
      id: Id attribute
      uri: URI attribute
      type: Type attribute
      transforms: Transforms elements
      digest_method: DigestMethod elements
      digest_value: DigestValue elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.id = id
    self.uri = uri
    self.type = type
    self.transforms = transforms or []
    self.digest_method = digest_method or []
    self.digest_value = digest_value or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def ReferenceFromString(xml_string):
  return saml2.CreateClassFromXMLString(Reference, xml_string)


class HMACOutputLength(DsBase):
  """The ds:HMACOutputLength element"""

  _tag = 'HMACOutputLength'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()

def HMACOutputLengthFromString(xml_string):
  return saml2.CreateClassFromXMLString(HMACOutputLength, xml_string)


class SignatureMethod(DsBase):
  """The ds:SignatureMethod element"""

  _tag = 'SignatureMethod'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Algorithm'] = "algorithm"
  _children['{%s}HMACOutputLength' % DS_NAMESPACE] = (
    'hmac_output_length', HMACOutputLength)

  def __init__(self, algorithm=None, hmac_output_length=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for SignatureMethod

    Args:
      algorighm: Algorithm attribute
      hmac_output_length: HMACOutputLength element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.algorithm = algorithm
    self.hmac_output_length = hmac_output_length
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def SignatureMethodFromString(xml_string):
  return saml2.CreateClassFromXMLString(SignatureMethod, xml_string)


class CanonicalizationMethod(DsBase):
  """The ds:CanonicalizationMethod element"""

  _tag = 'CanonicalizationMethod'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Algorithm'] = "algorithm"

  def __init__(self, algorithm=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for CanonicalizationMethod

    Args:
      algorighm: Algorithm attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.algorithm = algorithm
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def CanonicalizationMethodFromString(xml_string):
  return saml2.CreateClassFromXMLString(CanonicalizationMethod, xml_string)


class SignedInfo(DsBase):
  """The ds:SignedInfo element"""

  _tag = 'SignedInfo'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Id'] = "id"
  _children['{%s}CanonicalizationMethod' % DS_NAMESPACE] = (
    'canonicalization_method', CanonicalizationMethod)
  _children['{%s}SignatureMethod' % DS_NAMESPACE] = (
    'signature_method', SignatureMethod)
  _children['{%s}Reference' % DS_NAMESPACE] = ('reference', [Reference])
  _child_order = ['canonicalization_method', 'signature_method',
                  'reference']

  def __init__(self, id=None, canonicalization_method=None,
               signature_method=None, reference=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for SignedInfo

    Args:
      id: Id attribute
      canonicalization_method: CanonicalizationMethod element
      signature_method: SignatureMethod element
      reference: Reference elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.id = id
    self.canonicalization_method = canonicalization_method
    self.signature_method = signature_method
    self.reference = reference or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def SignedInfoFromString(xml_string):
  return saml2.CreateClassFromXMLString(SignedInfo, xml_string)


class SignatureValue(DsBase):
  """The ds:SignatureValue element"""

  _tag = 'SignatureValue'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Id'] = "id"

  def __init__(self, id=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for SignatureValue

    Args:
      id: Id attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.id = id
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def SignatureValueFromString(xml_string):
  return saml2.CreateClassFromXMLString(SignatureValue, xml_string)


class Signature(DsBase):
  """The ds:Signature element"""

  _tag = 'Signature'
  _namespace = DS_NAMESPACE
  _children = DsBase._children.copy()
  _attributes = DsBase._attributes.copy()
  _attributes['Id'] = "id"
  _children['{%s}SignedInfo' % DS_NAMESPACE] = ('signed_info', SignedInfo)
  _children['{%s}SignatureValue' % DS_NAMESPACE] = (
    'signature_value', SignatureValue)
  _children['{%s}KeyInfo' % DS_NAMESPACE] = ('key_info', KeyInfo)
  _children['{%s}Object' % DS_NAMESPACE] = ('object', [Object])
  _child_order = ["signed_info", "signature_value", "key_info", "object"]

  def __init__(self, id=None, signed_info=None, signature_value=None,
               key_info=None, object=None,
               extension_elements=None, extension_attributes=None, text=None):
    """Constructor for Signature

    Args:
      id: Id attribute
      signed_info: SignedInfo element
      signature_value: SignatureValue element
      key_info: KeyInfo element
      object: Object elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.id = id
    self.signed_info = signed_info
    self.signature_value = signature_value
    self.key_info = key_info
    self.object = object or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}


def SignatureFromString(xml_string):
  return saml2.CreateClassFromXMLString(Signature, xml_string)


def GetEmptySignature(canonicalization_method_algorithm=C14N_WITH_C,
                      signature_method_algorithm=SIG_RSA_SHA1,
                      transform_algorithm=TRANSFORM_ENVELOPED,
                      digest_algorithm=DIGEST_SHA1):

  canonicalization_method = CanonicalizationMethod(
    algorithm=canonicalization_method_algorithm)
  signature_method = SignatureMethod(algorithm=signature_method_algorithm)
  transforms = Transforms(transform=Transform(algorithm=transform_algorithm))
  digest_method = DigestMethod(algorithm=digest_algorithm)
  reference = Reference(uri="", transforms=transforms,
                        digest_method=digest_method,
                        digest_value=DigestValue())
  signed_info = SignedInfo(
    canonicalization_method=canonicalization_method,
    signature_method=signature_method,
    reference=reference)
  signature = Signature(signed_info=signed_info,
                        signature_value=SignatureValue(),
                        key_info=KeyInfo(key_value=KeyValue()))
  return signature

