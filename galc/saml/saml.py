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

"""Contains objects used with SAML-2."""

__author__ = 'tmatsuo@sios.com (Takashi MATSUO)'

"""Contains classes representing Saml elements.

  Module objective: provide data classes for Saml constructs. These
  classes hide the XML-ness of Saml and provide a set of native Python
  classes to interact with.

  Conversions to and from XML should only be necessary when the Saml classes
  "touch the wire" and are sent over HTTP. For this reason this module 
  provides  methods and functions to convert Saml classes to and from strings.

  SamlBase: A foundation class on which Saml classes are built. It 
      handles the parsing of attributes and children which are common to all
      Saml classes. By default, the SamlBase class translates all XML child 
      nodes into ExtensionElements.

  ExtensionElement: XML which is not part of the Saml specification,
      these are called extension elements. If a classes parser
      encounters an unexpected XML construct, it is translated into an
      ExtensionElement instance. ExtensionElement is designed to fully
      capture the information in the XML. Child nodes in an XML
      extension are turned into ExtensionElements as well.
"""

try:
  from xml.etree import cElementTree as ElementTree
except ImportError:
  try:
    import cElementTree as ElementTree
  except ImportError:
    from elementtree import ElementTree

import xmldsig as ds
import saml2

SAML_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion'
SAML_TEMPLATE = '{urn:oasis:names:tc:SAML:2.0:assertion}%s'
XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'

NAMEID_FORMAT_EMAILADDRESS = (
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
NAMEID_FORMAT_UNSPECIFIED = (
  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
NAMEID_FORMAT_ENCRYPTED = (
  "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted")
NAMEID_FORMAT_PERSISTENT = (
  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")

URN_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
NAME_FORMAT_UNSPECIFIED = (
  "urn:oasis:names:tc:SAML:2.0:attrnam-format:unspecified")
NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrnam-format:uri"
NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrnam-format:basic"
SUBJECT_CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

DECISION_TYPE_PERMIT = "Permit"
DECISION_TYPE_DENY = "Deny"
DECISION_TYPE_INDETERMINATE = "Indeterminate"

CONSENT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"
V2 = "2.0"

class BaseID(saml2.SamlBase):
  """The saml:BaseID element"""

  _tag = 'BaseID'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['NameQualifier'] = 'name_qualifier'
  _attributes['SPNameQualifier'] = 'sp_name_qualifier'

  def __init__(self, name_qualifier=None, sp_name_qualifier=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for BaseID

    Args:
      name_qualifier: NameQualifier attribute
      sp_name_qualifier: SPNameQualifier attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.name_qualifier = name_qualifier
    self.sp_name_qualifier = sp_name_qualifier
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def BaseIDFromString(xml_string):
  return saml2.CreateClassFromXMLString(BaseID, xml_string)

    
class NameID(BaseID):
  """The saml:NameID element"""

  _tag = 'NameID'
  _namespace = SAML_NAMESPACE
  _children = BaseID._children.copy()
  _attributes = BaseID._attributes.copy()
  _attributes['Format'] = 'format'
  _attributes['SPProvidedID'] = 'sp_provided_id'

  def __init__(self, name_qualifier=None, sp_name_qualifier=None, format=None,
               sp_provided_id=None, text=None, extension_elements=None,
               extension_attributes=None):
    """Constructor for NameID

    Args:
      format: Format attribute
      sp_provided_id: SPProvidedID attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    BaseID.__init__(self, name_qualifier=name_qualifier,
                    sp_name_qualifier=sp_name_qualifier)
    
    self.text = text
    self.format = format
    self.sp_provided_id = sp_provided_id
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def NameIDFromString(xml_string):
  return saml2.CreateClassFromXMLString(NameID, xml_string)


class Issuer(NameID):
  """The saml:Issuer element"""

  _tag = 'Issuer'
  _children = NameID._children.copy()
  _attributes = NameID._attributes.copy()

def IssuerFromString(xml_string):
  return saml2.CreateClassFromXMLString(Issuer, xml_string)


class SubjectLocality(saml2.SamlBase):
  """The saml:SubjectLocality element"""
  
  _tag = 'SubjectLocality'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['Address'] = 'address'
  _attributes['DNSName'] = 'dns_name'

  def __init__(self, address=None, dns_name=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for SubjectLocality

    Args:
      address: Address attribute
      dns_name: DNSName attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.address = address
    self.dns_name = dns_name
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def SubjectLocalityFromString(xml_string):
  return saml2.CreateClassFromXMLString(SubjectLocality, xml_string)


class AuthnContextClassRef(saml2.SamlBase):
  """The saml:AuthnContextClassRef element"""

  _tag = 'AuthnContextClassRef'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def AuthnContextClassRefFromString(xml_string):
  return saml2.CreateClassFromXMLString(AuthnContextClassRef, xml_string)


class AuthnContextDeclRef(saml2.SamlBase):
  """The saml:AuthnContextDeclRef element"""

  _tag = 'AuthnContextDeclRef'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def AuthnContextDeclRefFromString(xml_string):
  return saml2.CreateClassFromXMLString(AuthnContextDeclRef, xml_string)


class AuthnContextDecl(saml2.SamlBase):
  """The saml:AuthnContextDecl element"""

  _tag = 'AuthnContextDecl'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def AuthnContextDeclFromString(xml_string):
  return saml2.CreateClassFromXMLString(AuthnContextDecl, xml_string)


class AuthenticatingAuthority(saml2.SamlBase):
  """The saml:AuthenticatingAuthority element"""

  _tag = 'AuthenticatingAuthority'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def AuthenticatingAuthorityFromString(xml_string):
  return saml2.CreateClassFromXMLString(AuthenticatingAuthority, xml_string)


class AuthnContext(saml2.SamlBase):
  """The saml:AuthnContext element"""

  _tag = 'AuthnContext'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _children['{%s}AuthnContextClassRef' % SAML_NAMESPACE] = (
    'authn_context_class_ref', AuthnContextClassRef)
  _children['{%s}AuthnContextDeclRef' % SAML_NAMESPACE] = (
    'authn_context_decl_ref', AuthnContextDeclRef)
  _children['{%s}AuthnContextDecl' % SAML_NAMESPACE] = (
    'authn_context_decl', AuthnContextDecl)
  _children['{%s}AuthenticatingAuthority' % SAML_NAMESPACE] = (
    'authenticating_authority', [AuthenticatingAuthority])
  _child_order = ['authn_context_class_ref', 'authn_context_decl_ref',
                  'authn_context_decl', 'authenticating_authority']

  def __init__(self, authn_context_class_ref=None, authn_context_decl_ref=None,
               authn_context_decl=None, authenticating_authority=None,
               text=None, extension_elements=None, extension_attributes=None):
    """Constructor for AuthnContext

    Args:
      text: str The text data in the this element
      authn_context_class_ref: AuthnContextClassRef element
      authn_context_decl_ref: AuthnContextDeclRef element
      authn_context_decl: AuthnContextDecl element
      authenticating_authority: AuthenticatingAuthority element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.authn_context_class_ref = authn_context_class_ref
    self.authn_context_decl_ref = authn_context_decl_ref
    self.authn_context_decl = authn_context_decl
    self.authenticating_authority = authenticating_authority or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AuthnContextFromString(xml_string):
  return saml2.CreateClassFromXMLString(AuthnContext, xml_string)

class Statement(saml2.SamlBase):
  """The saml:Statement element"""

  _tag = 'Statement'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  
def StatementFromString(xml_string):
  return saml2.CreateClassFromXMLString(Statement, xml_string)


class AuthnStatement(Statement):
  """The saml:AuthnStatement element"""

  _tag = 'AuthnStatement'
  _namespace = SAML_NAMESPACE
  _children = Statement._children.copy()
  _attributes = Statement._attributes.copy()
  _attributes['AuthnInstant'] = 'authn_instant'
  _attributes['SessionIndex'] = 'session_index'
  _attributes['SessionNotOnOrAfter'] = 'session_not_on_or_after'
  _children['{%s}SubjectLocality' % SAML_NAMESPACE] = (
    'subject_locality', SubjectLocality)
  _children['{%s}AuthnContext' % SAML_NAMESPACE] = (
    'authn_context', AuthnContext)
  _child_order = ['subject_locality', 'authn_context']
  
  def __init__(self, authn_instant=None, session_index=None,
               session_not_on_or_after=None, subject_locality=None,
               authn_context=None, text=None, extension_elements=None,
               extension_attributes=None):
    """Constructor for AuthnStatement

    Args:
      authn_instant: AuthnInstant attribute
      session_index: SessionIndex attribute
      session_not_on_or_after: SessionNotOnOrAfter attribute
      subject_locality: SubjectLocality element
      authn_context: AuthnContext element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.authn_instant = authn_instant
    self.session_index = session_index
    self.session_not_on_or_after = session_not_on_or_after
    self.subject_locality = subject_locality
    self.authn_context = authn_context
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AuthnStatementFromString(xml_string):
  return saml2.CreateClassFromXMLString(AuthnStatement, xml_string)

# TODO: EncryptedAttribute

class AttributeValue(saml2.SamlBase):
  """The saml:AttributeValue element"""

  _tag = 'AttributeValue'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def AttributeValueFromString(xml_string):
  return saml2.CreateClassFromXMLString(AttributeValue, xml_string)


class Attribute(saml2.SamlBase):
  """The saml:Attribute element"""

  _tag = 'Attribute'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['Name'] = 'name'
  _attributes['NameFormat'] = 'name_format'
  _attributes['FriendlyName'] = 'friendly_name'
  _children['{%s}AttributeValue' % SAML_NAMESPACE] = \
                                 ('attribute_value', [AttributeValue])
  
  def __init__(self, name=None, name_format=None, friendly_name=None,
               attribute_value=None, text=None, extension_elements=None,
               extension_attributes=None):
    """Constructor for Attribute

    Args:
      name: Name attribute
      name_format: NameFormat attribute
      friendly_name: FriendlyName attribute
      attribute_value: AttributeValue elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.name = name
    self.name_format = name_format
    self.friendly_name = friendly_name
    self.attribute_value = attribute_value or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AttributeFromString(xml_string):
  return saml2.CreateClassFromXMLString(Attribute, xml_string)


class AttributeStatement(Statement):
  """The saml:AttributeStatement element"""

  # TODO: EncryptedAttribute
  _tag = 'AttributeStatement'
  _namespace = SAML_NAMESPACE
  _children = Statement._children.copy()
  _attributes = Statement._attributes.copy()
  _children['{%s}Attribute' % SAML_NAMESPACE] = \
                                 ('attribute', [Attribute])
  
  def __init__(self, attribute=None, text=None, extension_elements=None,
               extension_attributes=None):
    """Constructor for AttributeStatement

    Args:
      attribute: Attribute elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.attribute = attribute or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AttributeStatementFromString(xml_string):
  return saml2.CreateClassFromXMLString(AttributeStatement, xml_string)

# TODO: AuthzDecisionStatement

class Action(saml2.SamlBase):
  """The saml:Action element"""

  _tag = 'Action'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['Namespace'] = 'namespace'
  
  def __init__(self, namespace=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for Action

    Args:
      namespace: Namespace attribute
      text: str The text data in this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.namespace = namespace
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def ActionFromString(xml_string):
  return saml2.CreateClassFromXMLString(Action, xml_string)


class SubjectConfirmationData(saml2.SamlBase):
  """The saml:SubjectConfirmationData element"""

  _tag = 'SubjectConfirmationData'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['NotBefore'] = 'not_before'
  _attributes['NotOnOrAfter'] = 'not_on_or_after'
  _attributes['Recipient'] = 'recipient'
  _attributes['InResponseTo'] = 'in_response_to'
  _attributes['Address'] = 'address'
  
  def __init__(self, not_before=None, not_on_or_after=None, recipient=None,
               in_response_to=None, address=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for SubjectConfirmationData

    Args:
      not_before: NotBefore attribute
      not_on_or_after: NotOnOrAfter attribute
      recipient: Recipient attribute
      in_response_to: InResponseTo attribute
      address: Address attribute
      text: str The text data in this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.not_before = not_before
    self.not_on_or_after = not_on_or_after
    self.recipient = recipient
    self.in_response_to = in_response_to
    self.address = address
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def SubjectConfirmationDataFromString(xml_string):
  return saml2.CreateClassFromXMLString(SubjectConfirmationData, xml_string)


class SubjectConfirmation(saml2.SamlBase):
  """The saml:SubjectConfirmation element"""
  # TODO: BaseID, EncryptedID element

  _tag = 'SubjectConfirmation'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['Method'] = 'method'
  _children['{%s}NameID' % SAML_NAMESPACE] = ('name_id', NameID)
  _children['{%s}SubjectConfirmationData' % SAML_NAMESPACE] = (
    'subject_confirmation_data', SubjectConfirmationData)
  _child_order = ['name_id', 'subject_confirmation_data']

  def __init__(self, method=None, name_id=None, subject_confirmation_data=None,
               text=None, extension_elements=None, extension_attributes=None):
    """Constructor for SubjectConfirmation

    Args:
      method: Method attribute
      name_id: NameID element
      subject_confirmation_data: SubjectConfirmationData element
      text: str The text data in this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.method = method
    self.name_id = name_id
    self.subject_confirmation_data = subject_confirmation_data
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def SubjectConfirmationFromString(xml_string):
  return saml2.CreateClassFromXMLString(SubjectConfirmation, xml_string)


class Subject(saml2.SamlBase):
  """The saml:Subject element"""
  # TODO: BaseID, EncryptedID element

  _tag = 'Subject'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _children['{%s}NameID' % SAML_NAMESPACE] = ('name_id', NameID)
  _children['{%s}SubjectConfirmation' % SAML_NAMESPACE] = (
    'subject_confirmation', [SubjectConfirmation])
  _child_order = ['name_id', 'subject_confirmation']

  def __init__(self, name_id=None, subject_confirmation=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for SubjectConfirmation

    Args:
      name_id: NameID element
      subject_confirmation: SubjectConfirmation element
      text: str The text data in this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.name_id = name_id
    self.subject_confirmation = subject_confirmation or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def SubjectFromString(xml_string):
  return saml2.CreateClassFromXMLString(Subject, xml_string)


class Condition(saml2.SamlBase):
  """The saml:Condition element"""

  _tag = 'Condition'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def ConditionFromString(xml_string):
  return saml2.CreateClassFromXMLString(Condition, xml_string)


class Audience(saml2.SamlBase):
  """The saml:Audience element"""

  _tag = 'Audience'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def AudienceFromString(xml_string):
  return saml2.CreateClassFromXMLString(Audience, xml_string)


class AudienceRestriction(Condition):
  """The saml:AudienceRestriction element"""

  _tag = 'AudienceRestriction'
  _namespace = SAML_NAMESPACE
  _children = Condition._children.copy()
  _attributes = Condition._attributes.copy()
  _children['{%s}Audience' % SAML_NAMESPACE] = ('audience', Audience)

  def __init__(self, text=None, audience=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for AudienceRestriction

    Args:
      audience: Audience element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.audience = audience
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AudienceRestrictionFromString(xml_string):
  return saml2.CreateClassFromXMLString(AudienceRestriction, xml_string)

class OneTimeUse(Condition):
  """The saml:OneTimeUse element"""
  
  _tag = 'OneTimeUse'
  _children = Condition._children.copy()
  _attributes = Condition._attributes.copy()

def OneTimeUseFromString(xml_string):
  return saml2.CreateClassFromXMLString(OneTimeUse, xml_string)


class ProxyRestriction(Condition):
  """The saml:Condition element"""

  _tag = 'ProxyRestriction'
  _namespace = SAML_NAMESPACE
  _children = Condition._children.copy()
  _attributes = Condition._attributes.copy()
  _attributes['Count'] = 'count'
  _children['{%s}Audience' % SAML_NAMESPACE] = ('audience', [Audience])

  def __init__(self, text=None, count=None, audience=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for ProxyRestriction

    Args:
      text: str The text data in this element
      count: Count attribute
      audience: Audience elements
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.count = count
    self.audience = audience or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def ProxyRestrictionFromString(xml_string):
  return saml2.CreateClassFromXMLString(ProxyRestriction, xml_string)


class Conditions(saml2.SamlBase):
  """The saml:Conditions element"""

  _tag = 'Conditions'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()  
  _attributes['NotBefore'] = 'not_before'
  _attributes['NotOnOrAfter'] = 'not_on_or_after'
  _children['{%s}Condition' % SAML_NAMESPACE] = ('condition', [Condition])
  _children['{%s}AudienceRestriction' % SAML_NAMESPACE] = (
    'audience_restriction', [AudienceRestriction])
  _children['{%s}OneTimeUse' % SAML_NAMESPACE] = (
    'one_time_use', [OneTimeUse])
  _children['{%s}ProxyRestriction' % SAML_NAMESPACE] = (
    'proxy_restriction', [ProxyRestriction])
  _child_order = ['condition', 'audience_restriction', 'one_time_use',
                  'proxy_restriction']

  def __init__(self, text=None, not_before=None, not_on_or_after=None,
               condition=None, audience_restriction=None, one_time_use=None,
               proxy_restriction=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for ProxyRestriction

    Args:
      text: str The text data in this element
      not_before: NotBefore attribute
      not_on_or_after: NotOnOrAfter attribute
      condition: Condition elements
      audience_restriction: AudienceRestriction elements
      one_time_use: OneTimeUse elements
      proxy_restriction: ProxyRestriction elements
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.not_before = not_before
    self.not_on_or_after = not_on_or_after
    self.condition = condition or []
    self.audience_restriction = audience_restriction or []
    self.one_time_use = one_time_use or []
    self.proxy_restriction = proxy_restriction or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def ConditionsFromString(xml_string):
  return saml2.CreateClassFromXMLString(Conditions, xml_string)


class AssertionIDRef(saml2.SamlBase):
  """The saml:AssertionIDRef element"""
  _tag = 'AssertionIDRef'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def AssertionIDRefFromString(xml_string):
  return saml2.CreateClassFromXMLString(AssertionIDRef, xml_string)


class AssertionURIRef(saml2.SamlBase):
  """The saml:AssertionURIRef element"""
  _tag = 'AssertionURIRef'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def AssertionURIRefFromString(xml_string):
  return saml2.CreateClassFromXMLString(AssertionURIRef, xml_string)


class Evidence(saml2.SamlBase):
  """The saml:Evidence element"""

  _tag = 'Evidence'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _children['{%s}AssertionIDRef' % SAML_NAMESPACE] = \
                                 ('assertion_id_ref', [AssertionIDRef])
  _children['{%s}AssertionURIRef' % SAML_NAMESPACE] = \
                                 ('assertion_uri_ref', [AssertionURIRef])
  
  def __init__(self, assertion_id_ref=None, assertion_uri_ref=None,
               assertion=None, encrypted_assertion=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for Evidence

    Args:
      assertion_id_ref: AssertionIDRef elements
      assertion_uri_ref: AssertionURIRef elements
      assertion: Assertion elements
      encrypted_assertion: EncryptedAssertion elements
      text: str The text data in this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.assertion_id_ref = assertion_id_ref or []
    self.assertion_uri_ref = assertion_uri_ref or []
    self.assertion = assertion or []
    self.encrypted_assertion = encrypted_assertion or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def EvidenceFromString(xml_string):
  return saml2.CreateClassFromXMLString(Evidence, xml_string)

class Advice(saml2.SamlBase):
  """The saml:Advice element"""

  _tag = 'Advice'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _children['{%s}AssertionIDRef' % SAML_NAMESPACE] = \
                                 ('assertion_id_ref', [AssertionIDRef])
  _children['{%s}AssertionURIRef' % SAML_NAMESPACE] = \
                                 ('assertion_uri_ref', [AssertionURIRef])
  
  def __init__(self, assertion_id_ref=None, assertion_uri_ref=None,
               assertion=None, encrypted_assertion=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for Advice

    Args:
      assertion_id_ref: AssertionIDRef elements
      assertion_uri_ref: AssertionURIRef elements
      assertion: Assertion elements
      encrypted_assertion: EncryptedAssertion elements
      text: str The text data in this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.assertion_id_ref = assertion_id_ref or []
    self.assertion_uri_ref = assertion_uri_ref or []
    self.assertion = assertion or []
    self.encrypted_assertion = encrypted_assertion or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AdviceFromString(xml_string):
  return saml2.CreateClassFromXMLString(Advice, xml_string)


class Assertion(saml2.SamlBase):
  """The saml:Assertion element"""
  _tag = 'Assertion'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['Version'] = 'version'
  _attributes['ID'] = 'id'
  _attributes['IssueInstant'] = 'issue_instant'
  _children['{%s}Issuer' % SAML_NAMESPACE] = ('issuer', Issuer)
  _children['{%s}Signature' % ds.DS_NAMESPACE] = ('signature', ds.Signature)
  _children['{%s}Subject' % SAML_NAMESPACE] = ('subject', Subject)
  _children['{%s}Conditions' % SAML_NAMESPACE] = ('conditions', Conditions)
  _children['{%s}Advice' % SAML_NAMESPACE] = ('advice', Advice)
  _children['{%s}Statement' % SAML_NAMESPACE] = ('statement', [Statement])
  _children['{%s}AuthnStatement' % SAML_NAMESPACE] = (
    'authn_statement', [AuthnStatement])
  _children['{%s}AttributeStatement' % SAML_NAMESPACE] = (
    'attribute_statement', [AttributeStatement])
  _child_order = ['issuer', 'signature', 'subject', 'conditions', 'advice',
                  'statement', 'authn_statement', 'authz_decision_statement',
                  'attribute_statement']

  def __init__(self, version=None, id=None, issue_instant=None, issuer=None,
               signature=None, subject=None, conditions=None, advice=None,
               statement=None, authn_statement=None,
               authz_decision_statement=None, attribute_statement=None,
               text=None, extension_elements=None, extension_attributes=None):
    """Constructor for Assertion

    Args:
      version: Version attribute
      id: ID attribute
      issue_instant: IssueInstant attribute
      issuer: Issuer element
      signature: ds:Signature element
      subject: Subject element
      conditions: Conditions element
      advice: Advice element
      statement: Statement elements
      authn_statement: AuthnStatement elements
      authz_decision_statement: AuthzDecisionStatement elements
      attribute_statement: AttributeStatement elements
      text: str The text data in this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.version = version
    self.id = id
    self.issue_instant = issue_instant
    self.issuer = issuer
    self.signature = signature
    self.subject = subject
    self.conditions = conditions
    self.advice = advice
    self.statement = statement or []
    self.authn_statement = authn_statement or []
    self.authz_decision_statement = authz_decision_statement or []
    self.attribute_statement = attribute_statement or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AssertionFromString(xml_string):
  return saml2.CreateClassFromXMLString(Assertion, xml_string)

Evidence._children['{%s}Assertion' % SAML_NAMESPACE] = (
  'assertion', [Assertion])
Advice._children['{%s}Assertion' % SAML_NAMESPACE] = (
  'assertion', [Assertion])


class EncryptedID(saml2.SamlBase):
  """The saml:EncryptedID element"""
  _tag = 'EncryptedID'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

  # TODO: This is just a skelton yet.

def EncryptedIDFromString(xml_string):
  return saml2.CreateClassFromXMLString(EncryptedID, xml_string)


class EncryptedAssertion(saml2.SamlBase):
  """The saml:EncryptedAssertion element"""
  _tag = 'EncryptedAssertion'
  _namespace = SAML_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

  # TODO: This is just a skelton yet.

def EncryptedAssertionFromString(xml_string):
  return saml2.CreateClassFromXMLString(EncryptedAssertion, xml_string)

Evidence._children['{%s}EncryptedAssertion' % SAML_NAMESPACE] = (
  'encrypted_assertion', [EncryptedAssertion])
Advice._children['{%s}EncryptedAssertion' % SAML_NAMESPACE] = (
  'encrypted_assertion', [EncryptedAssertion])

class AuthzDecisionStatement(Statement):
  """The saml:AuthzDecisionStatement element"""

  _tag = 'AuthzDecisionStatement'
  _namespace = SAML_NAMESPACE
  _children = Statement._children.copy()
  _attributes = Statement._attributes.copy()

  _attributes['Resource'] = 'resource'
  _attributes['Decision'] = 'decision'
  _children['{%s}Action' % SAML_NAMESPACE] = ('action', [Action])
  _children['{%s}Evidence' % SAML_NAMESPACE] = ('evidence', [Evidence])
  _child_order = ['action', 'evidence']

  def __init__(self, text=None, resource=None, decision=None, action=None,
               evidence=None, extension_elements=None,
               extension_attributes=None):
    """Constructor for AuthzDecisionStatement

    Args:
      text: str The text data in this element
      resource: Resource attribute
      decision: Decision attribute
      action: Action Elements
      evidence: Evidence Elements
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.text = text
    self.resource = resource
    self.decision = decision
    self.action = action or []
    self.evidence = evidence or []
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AuthzDecisionStatementFromString(xml_string):
  return saml2.CreateClassFromXMLString(AuthzDecisionStatement, xml_string)

Assertion._children['{%s}AuthzDecisionStatement' % SAML_NAMESPACE] = (
  'authz_decision_statement', [AuthzDecisionStatement])

