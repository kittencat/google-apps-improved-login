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

"""Contains classes representing Samlp elements.

  Module objective: provide data classes for Samlp constructs. These
  classes hide the XML-ness of Saml and provide a set of native Python
  classes to interact with.

"""

try:
  from xml.etree import cElementTree as ElementTree
except ImportError:
  try:
    import cElementTree as ElementTree
  except ImportError:
    from elementtree import ElementTree

import saml2
from saml2 import saml
import xmldsig as ds

SAMLP_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:protocol'
SAMLP_TEMPLATE = '{urn:oasis:names:tc:SAML:2.0:protocol}%s'

BINDING_SOAP = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'
BINDING_PAOS = 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS'
BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
BINDING_HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'
BINDING_URI = 'urn:oasis:names:tc:SAML:2.0:bindings:URI'

STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester'
STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder'
STATUS_VERSION_MISMATCH = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch'

STATUS_AUTHN_FAILED = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'
STATUS_INVALID_ATTR_NAME_OR_VALUE = (
  'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue')
STATUS_INVALID_NAMEID_POLICY = (
  'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy')
STATUS_NO_AUTHN_CONTEXT = 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext'
STATUS_NO_AVAILABLE_IDP = 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP'
STATUS_NO_PASSIVE = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive'
STATUS_NO_SUPPORTED_IDP = 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP'
STATUS_PARTIAL_LOGOUT = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout'
STATUS_PROXY_COUNT_EXCEEDED = (
  'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded')
STATUS_REQUEST_DENIED = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied'
STATUS_REQUEST_UNSUPPORTED = (
  'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported')
STATUS_REQUEST_VERSION_DEPRECATED = (
  'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated')
STATUS_REQUEST_VERSION_TOO_HIGH = (
  'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh')
STATUS_REQUEST_VERSION_TOO_LOW = (
  'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow')
STATUS_RESOURCE_NOT_RECOGNIZED = (
  'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized')
STATUS_TOO_MANY_RESPONSES = (
  'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses')
STATUS_UNKNOWN_ATTR_PROFILE = (
  'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile')
STATUS_UNKNOWN_PRINCIPAL = (
  'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal')
STATUS_UNSUPPORTED_BINDING = (
  'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding')

class Extensions(saml2.SamlBase):
  """The samlp:Extensions element"""

  _tag = 'Extensions'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def ExtensionsFromString(xml_string):
  return saml2.CreateClassFromXMLString(Extensions, xml_string)


class AbstractRequest(saml2.SamlBase):
  """The samlp:RequestAbstractType element"""

  _tag = 'AbstractRequest'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['ID'] = 'id'
  _attributes['Version'] = 'version'
  _attributes['IssueInstant'] = 'issue_instant'
  _attributes['Destination'] = 'destination'
  _attributes['Consent'] = 'consent'
  _children['{%s}Issuer' % saml.SAML_NAMESPACE] = ('issuer', saml.Issuer)
  _children['{%s}Signature' % ds.DS_NAMESPACE] = ('signature', ds.Signature)
  _children['{%s}Extensions' % SAMLP_NAMESPACE] = ('extensions', Extensions)
  _child_order = ['issuer', 'signature', 'extensions']

  def __init__(self, id=None, version=None, issue_instant=None,
               destination=None, consent=None, issuer=None, signature=None,
               extensions=None,
               text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for AbstractRequest

    Args:
      id: ID attribute
      version: Version attribute
      issue_instant: IssueInstant attribute
      destination: Destination attribute
      consent: Consent attribute
      issuer: Issuer element
      signature: Signature element
      extensions: Extensions element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.id = id
    self.version = version
    self.issue_instant = issue_instant
    self.destination = destination
    self.consent = consent
    self.issuer = issuer
    self.signature = signature
    self.extensions = extensions
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AbstractRequestFromString(xml_string):
  return saml2.CreateClassFromXMLString(AbstractRequest, xml_string)

class StatusDetail(saml2.SamlBase):
  """The samlp:StatusDetail element"""
  _tag = 'StatusDetail'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def StatusDetailFromString(xml_string):
  return saml2.CreateClassFromXMLString(StatusDetail, xml_string)

class StatusMessage(saml2.SamlBase):
  """The samlp:StatusMessage element"""
  _tag = 'StatusMessage'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def StatusMessageFromString(xml_string):
  return saml2.CreateClassFromXMLString(StatusMessage, xml_string)

class StatusCode(saml2.SamlBase):
  """The samlp:StatusCode element"""
  _tag = 'StatusCode'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['Value'] = 'value'
  
  def __init__(self, value=None, status_code=None,
               text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for Status

    Args:
      value: Value attribute
      status_code: StatusCode element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.value = value
    self.status_code = status_code
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def StatusCodeFromString(xml_string):
  return saml2.CreateClassFromXMLString(StatusCode, xml_string)

StatusCode._children['{%s}StatusCode' % SAMLP_NAMESPACE] = (
  'status_code', StatusCode)


class Status(saml2.SamlBase):
  """The samlp:Status element"""

  _tag = 'Status'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _children['{%s}StatusCode' % SAMLP_NAMESPACE] = ('status_code', StatusCode)
  _children['{%s}StatusMessage' % SAMLP_NAMESPACE] = (
    'status_message', StatusMessage)
  _children['{%s}StatusDetail' % SAMLP_NAMESPACE] = (
    'status_detail', StatusDetail)
  _child_order = ['status_code', 'status_message', 'status_detail']

  def __init__(self, status_code=None, status_message=None, status_detail=None,
               text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for Status

    Args:
      status_code: StatusCode element
      status_message: StatusMessage element
      status_detail: StatusDetail element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.status_code = status_code
    self.status_message = status_message
    self.status_detail = status_detail
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def StatusFromString(xml_string):
  return saml2.CreateClassFromXMLString(Status, xml_string)


class StatusResponse(saml2.SamlBase):
  """The samlp:StatusResponse element"""

  _tag = 'StatusResponse'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['ID'] = 'id'
  _attributes['InResponseTo'] = 'in_response_to'
  _attributes['Version'] = 'version'
  _attributes['IssueInstant'] = 'issue_instant'
  _attributes['Destination'] = 'destination'
  _attributes['Consent'] = 'consent'
  _children['{%s}Issuer' % saml.SAML_NAMESPACE] = ('issuer', saml.Issuer)
  _children['{%s}Signature' % ds.DS_NAMESPACE] = ('signature', ds.Signature)
  _children['{%s}Extensions' % SAMLP_NAMESPACE] = ('extensions', Extensions)
  _children['{%s}Status' % SAMLP_NAMESPACE] = ('status', Status)
  _child_order = ['issuer', 'signature', 'extensions', 'status']

  def __init__(self, id=None, in_response_to=None, version=None,
               issue_instant=None, destination=None, consent=None,
               issuer=None, signature=None, extensions=None, status=None,
               text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for StatusResponse

    Args:
      id: ID attribute
      in_respones_to: InResponseTo attribute
      version: Version attribute
      issue_instant: IssueInstant attribute
      destination: Destination attribute
      consent: Consent attribute
      issuer: Issuer element
      signature: Signature element
      extensions: Extensions element
      status: Status element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.id = id
    self.in_response_to = in_response_to
    self.version = version
    self.issue_instant = issue_instant
    self.destination = destination
    self.consent = consent
    self.issuer = issuer
    self.signature = signature
    self.extensions = extensions
    self.status = status
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def StatusResponseFromString(xml_string):
  return saml2.CreateClassFromXMLString(StatusResponse, xml_string)


class Response(StatusResponse):
  """The samlp:Response element"""

  _tag = 'Response'
  _namespace = SAMLP_NAMESPACE
  _children = StatusResponse._children.copy()
  _attributes = StatusResponse._attributes.copy()
  _children['{%s}Assertion' % saml.SAML_NAMESPACE] = (
    'assertion', [saml.Assertion])
  _children['{%s}EncryptedAssertion' % saml.SAML_NAMESPACE] = (
    'encrypted_assertion', [saml.EncryptedAssertion])
  _child_order = ['issuer', 'signature', 'extensions', 'status', 'assertion',
                  'encrypted_assertion']

  def __init__(self, id=None, in_response_to=None, version=None,
               issue_instant=None, destination=None, consent=None,
               issuer=None, signature=None, extensions=None, status=None,
               assertion=None, encrypted_assertion=None,
               text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for Response

    Args:
      id: ID attribute
      in_respones_to: InResponseTo attribute
      version: Version attribute
      issue_instant: IssueInstant attribute
      destination: Destination attribute
      consent: Consent attribute
      issuer: Issuer element
      signature: Signature element
      extensions: Extensions element
      status: Status element
      assertion: Assertion elements
      encrypted_assertion: EncryptedAssertion elements
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """
    StatusResponse.__init__(self, id=id, in_response_to=in_response_to,
                            version=version, issue_instant=issue_instant,
                            destination=destination, consent=consent,
                            issuer=issuer, signature=signature,
                            extensions=extensions, status=status)
    self.assertion = assertion or []
    self.encrypted_assertion = encrypted_assertion or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def ResponseFromString(xml_string):
  return saml2.CreateClassFromXMLString(Response, xml_string)


class NameIDPolicy(saml2.SamlBase):
  """The samlp:NameIDPolicy element"""

  _tag = 'NameIDPolicy'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['Format'] = 'format'
  _attributes['SPNameQualifier'] = 'sp_name_qualifier'
  _attributes['AllowCreate'] = 'allow_create'

  def __init__(self, format=None, sp_name_qualifier=None, allow_create=None,
               text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for NameIDPolicy

    Args:
      format: Format attribute
      sp_name_qualifier: SPNameQualifier attribute
      allow_create: AllowCreate attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.format = format
    self.sp_name_qualifier = sp_name_qualifier
    self.allow_create = allow_create
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def NameIDPolicyFromString(xml_string):
  return saml2.CreateClassFromXMLString(NameIDPolicy, xml_string)


class IDPEntry(saml2.SamlBase):
  """The samlp:IDPEntry element"""

  _tag = 'IDPEntry'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['ProviderID'] = 'provider_id'
  _attributes['Name'] = 'name'
  _attributes['Loc'] = 'loc'

  def __init__(self, provider_id=None, name=None, loc=None,
               text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for IDPEntry

    Args:
      provider_id: ProviderID attribute
      name: Name attribute
      loc: Loc attribute
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.provider_id = provider_id
    self.name = name
    self.loc = loc
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def IDPEntryFromString(xml_string):
  return saml2.CreateClassFromXMLString(IDPEntry, xml_string)


class GetComplete(saml2.SamlBase):
  """The samlp:GetComplete element"""

  _tag = 'GetComplete'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def GetCompleteFromString(xml_string):
  return saml2.CreateClassFromXMLString(GetComplete, xml_string)


class IDPList(saml2.SamlBase):
  """The samlp:IDPList element"""

  _tag = 'IDPList'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _children['{%s}IDPEntry' % SAMLP_NAMESPACE] = ('idp_entry', [IDPEntry])
  _children['{%s}GetComplete' % SAMLP_NAMESPACE] = (
    'get_complete', GetComplete)
  _child_order = ['idp_entry', 'get_complete']

  def __init__(self, idp_entry=None, get_complete=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for IDPList

    Args:
      idp_entry: IDPEntry elements
      get_complete: GetComplete element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.idp_entry = idp_entry or []
    self.get_complete = get_complete
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def IDPListFromString(xml_string):
  return saml2.CreateClassFromXMLString(IDPList, xml_string)


class RequesterID(saml2.SamlBase):
  """The samlp:RequesterID element"""
  _tag = 'RequesterID'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def RequesterIDFromString(xml_string):
  return saml2.CreateClassFromXMLString(RequesterID, xml_string)


class Scoping(saml2.SamlBase):
  """The samlp:Scoping element"""

  _tag = 'Scoping'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['ProxyCount'] = 'proxy_count'
  _children['{%s}IDPList' % SAMLP_NAMESPACE] = ('idp_list', IDPList)
  _children['{%s}RequesterID' % SAMLP_NAMESPACE] = (
    'requester_id', [RequesterID])
  _child_order = ['idp_list', 'requester_id']

  def __init__(self, proxy_count=None, idp_list=None, requester_id=None,
               text=None, extension_elements=None, extension_attributes=None):
    """Constructor for Scoping

    Args:
      proxy_count: ProxyCount attribute
      idp_list: IDPList element
      requester_id: list A list of RequesterID instances
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.proxy_count = proxy_count
    self.idp_list = idp_list
    self.requester_id = requester_id or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def ScopingFromString(xml_string):
  return saml2.CreateClassFromXMLString(Scoping, xml_string)


class RequestedAuthnContext(saml2.SamlBase):
  """The samlp:RequestedAuthnContext element"""

  _tag = 'RequestedAuthnContext'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()
  _attributes['Comparison'] = 'comparison'
  _children['{%s}AuthnContextClassRef' % saml.SAML_NAMESPACE] = (
    'authn_context_class_ref', [saml.AuthnContextClassRef])
  _children['{%s}AuthnContextDeclRef' % saml.SAML_NAMESPACE] = (
    'authn_context_decl_ref', [saml.AuthnContextDeclRef])

  def __init__(self, comparison=None, authn_context_class_ref=None,
               authn_context_decl_ref=None,
               text=None, extension_elements=None, extension_attributes=None):
    """Constructor for RequestedAuthnContext

    Args:
      comparison: Comparison attribute
      authn_context_class_ref: list A list of AuthnContextClassRef instances
      authn_context_decl_ref: list A list of AuthnContextDeclRef instances
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """

    self.comparison = comparison
    self.authn_context_class_ref = authn_context_class_ref or []
    self.authn_context_decl_ref = authn_context_decl_ref or []
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def RequestedAuthnContextFromString(xml_string):
  return saml2.CreateClassFromXMLString(RequestedAuthnContext, xml_string)


class AuthnRequest(AbstractRequest):
  """The samlp:AuthnRequest element"""

  _tag = 'AuthnRequest'
  _namespace = SAMLP_NAMESPACE
  _children = AbstractRequest._children.copy()
  _attributes = AbstractRequest._attributes.copy()
  _attributes['ForceAuthn'] = 'force_authn'
  _attributes['IsPassive'] = 'is_passive'
  _attributes['AssertionConsumerServiceIndex'] = (
    'assertion_consumer_service_index')
  _attributes['AssertionConsumerServiceURL'] = 'assertion_consumer_service_url'
  _attributes['ProtocolBinding'] = 'protocol_binding'
  _attributes['AssertionConsumingServiceIndex'] = (
    'assertion_consuming_service_index')
  _attributes['ProviderName'] = 'provider_name'
  _children['{%s}Subject' % saml.SAML_NAMESPACE] = ('subject', saml.Subject)
  _children['{%s}NameIDPolicy' % SAMLP_NAMESPACE] = (
    'name_id_policy', NameIDPolicy)
  _children['{%s}Conditions' % saml.SAML_NAMESPACE] = (
    'conditions', saml.Conditions)
  _children['{%s}RequestedAuthnContext' % SAMLP_NAMESPACE] = (
    'requested_authn_context', RequestedAuthnContext)
  _children['{%s}Scoping' % SAMLP_NAMESPACE] = ('scoping', Scoping)
  _child_order = ['issuer', 'signature', 'extensions', 'subject',
                  'name_id_policy', 'conditions', 'requested_authn_context',
                  'scoping']

  def __init__(self, id=None, version=None, issue_instant=None,
               destination=None, consent=None, issuer=None, signature=None,
               extensions=None, subject=None, name_id_policy=None,
               conditions=None, requested_authn_context=None, scoping=None,
               force_authn=None, is_passive=None,
               assertion_consumer_service_index=None,
               assertion_consumer_service_url=None,
               protocol_binding=None, assertion_consuming_service_index=None,
               provider_name=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for AuthnRequest

    Args:
      id: ID attribute
      version: Version attribute
      issue_instant: IssueInstant attribute
      destination: Destination attribute
      consent: Consent attribute
      issuer: Issuer element
      signature: Signature element
      extensions: Extensions element
      subject: Subject element
      name_id_policy: NameIDPolicy element
      conditions: Conditions element
      requested_authn_context: RequestedAuthnContext element
      scoping: Scoping element
      force_authn: ForceAuthn attribute
      is_passive: IsPassive attribute
      assertion_consumer_service_index: AssertionConsumerServiceIndex element
      assertion_consumer_service_url: AssertionConsumerServiceURL element
      protocol_binding: ProtocolBinding element
      assertion_consuming_service_index: AssertionConsumingServiceIndex element
      provider_name: ProviderName element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """
    AbstractRequest.__init__(self, id=id, version=version,
                             issue_instant=issue_instant,
                             destination=destination, consent=consent,
                             issuer=issuer, signature=signature,
                             extensions=extensions)
    self.subject = subject
    self.name_id_policy = name_id_policy
    self.conditions = conditions
    self.requested_authn_context = requested_authn_context
    self.conditions = conditions
    self.requested_authn_context = requested_authn_context
    self.scoping = scoping
    self.force_authn = force_authn
    self.is_passive = is_passive
    self.assertion_consumer_service_index = assertion_consumer_service_index
    self.assertion_consumer_service_url = assertion_consumer_service_url
    self.protocol_binding = protocol_binding
    self.assertion_consuming_service_index = assertion_consuming_service_index
    self.provider_name = provider_name
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def AuthnRequestFromString(xml_string):
  return saml2.CreateClassFromXMLString(AuthnRequest, xml_string)


class SessionIndex(saml2.SamlBase):
  """The samlp:SessionIndex element"""
  _tag = 'SessionIndex'
  _namespace = SAMLP_NAMESPACE
  _children = saml2.SamlBase._children.copy()
  _attributes = saml2.SamlBase._attributes.copy()

def SessionIndexFromString(xml_string):
  return saml2.CreateClassFromXMLString(SessionIndex, xml_string)


class LogoutRequest(AbstractRequest):
  """The samlp:LogoutRequest element"""

  _tag = 'LogoutRequest'
  _namespace = SAMLP_NAMESPACE
  _children = AbstractRequest._children.copy()
  _attributes = AbstractRequest._attributes.copy()
  _attributes['NotOnOrAfter'] = 'not_on_or_after'
  _attributes['Reason'] = 'reason'
  _children['{%s}BaseID' % saml.SAML_NAMESPACE] = ('base_id', saml.BaseID)
  _children['{%s}NameID' % saml.SAML_NAMESPACE] = ('name_id', saml.NameID)
  _children['{%s}EncryptedID' % saml.SAML_NAMESPACE] = (
    'encrypted_id', saml.EncryptedID)
  _children['{%s}SessionIndex' % SAMLP_NAMESPACE] = (
    'session_index', SessionIndex)
  _child_order = ['issuer', 'signature', 'extensions', 'base_id', 'name_id',
                  'encrypted_id', 'session_index']

  def __init__(self, id=None, version=None, issue_instant=None,
               destination=None, consent=None, issuer=None, signature=None,
               extensions=None, not_on_or_after=None, reason=None,
               base_id=None, name_id=None, encrypted_id=None,
               session_index=None, text=None,
               extension_elements=None, extension_attributes=None):
    """Constructor for LogoutRequest

    Args:
      id: ID attribute
      version: Version attribute
      issue_instant: IssueInstant attribute
      destination: Destination attribute
      consent: Consent attribute
      issuer: Issuer element
      signature: Signature element
      extensions: Extensions element
      not_on_or_after: NotOnOrAfter attribute
      reason: Reason attribute
      base_id: BaseID element
      name_id: NameID element
      encrypted_id: EncryptedID element
      session_index: SessionIndex element
      text: str The text data in the this element
      extension_elements: list A  list of ExtensionElement instances
      extension_attributes: dict A dictionary of attribute value string pairs
    """
    AbstractRequest.__init__(self, id=id, version=version,
                             issue_instant=issue_instant,
                             destination=destination, consent=consent,
                             issuer=issuer, signature=signature,
                             extensions=extensions)
    self.not_on_or_after = not_on_or_after
    self.reason = reason
    self.base_id = base_id
    self.name_id = name_id
    self.encrypted_id = encrypted_id
    self.session_index = session_index
    self.text = text
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}

def LogoutRequestFromString(xml_string):
  return saml2.CreateClassFromXMLString(LogoutRequest, xml_string)


class LogoutResponse(StatusResponse):
  """The samlp:LogoutResponse element"""

  _tag = 'LogoutResponse'
  _namespace = SAMLP_NAMESPACE
  _children = StatusResponse._children.copy()
  _attributes = StatusResponse._attributes.copy()

def LogoutResponseFromString(xml_string):
  return saml2.CreateClassFromXMLString(LogoutResponse, xml_string)
