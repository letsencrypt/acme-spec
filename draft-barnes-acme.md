---
title: "Automatic Certificate Management Environment (ACME)"
abbrev: ACME
docname: draft-barnes-acme-03
date: 2014-09-01
category: std
ipr: trust200902

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: R. Barnes
    name: Richard Barnes
    org: Mozilla
    email: rlb@ipv.sx
 -
    ins: P. Eckersley
    name: Peter Eckersley
    org: EFF
    email: pde@eff.org
 -
    ins: S. Schoen
    name: Seth Schoen
    org: EFF
    email: schoen@eff.org
 -
    ins: A. Halderman
    name: Alex Halderman
    org: University of Michigan
    email: jhalderm@eecs.umich.edu
 -
    ins: J. Kasten
    name: James Kasten
    org: University of Michigan
    email: jdkasten@umich.edu


normative:
  RFC2119:
  RFC2314:
  RFC2985:
  RFC2986:
  RFC3339:
  RFC3986:
  RFC4514:
  RFC5226:
  RFC5246:
  RFC5280:
  RFC5988:
  RFC6570:
  RFC7159:
  I-D.ietf-appsawg-http-problem:
  I-D.ietf-jose-json-web-algorithms:
  I-D.ietf-jose-json-web-key:
  I-D.ietf-jose-json-web-signature:

informative:
  RFC2818:


--- abstract

Certificates in the Web's X.509 PKI (PKIX) are used for a number of purposes, the most significant of which is the authentication of domain names.  Thus, certificate authorities in the Web PKI are trusted to verify that an applicant for a certificate legitimately represents the domain name(s) in the certificate.  Today, this verification is done through a collection of ad hoc mechanisms.  This document describes a protocol that a certificate authority (CA) and an applicant can use to automate the process of verification and certificate issuance.  The protocol also provides facilities for other certificate management functions, such as certificate revocation.


--- middle

# Introduction

Certificates in the Web PKI are most commonly used to authenticate domain names.  Thus, certificate authorities in the Web PKI are trusted to verify that an applicant for a certificate legitimately represents the domain name(s) in the certificate.

Existing Web PKI certificate authorities tend to run on a set of ad hoc protocols for certificate issuance and identity verification.  A typical user experience is something like:

* Generate a PKCS#10 {{RFC2314}} Certificate Signing Request (CSR).
* Cut-and-paste the CSR into a CA web page.
* Prove ownership of the domain by one of the following methods:
   * Put a CA-provided challenge at a specific place on the web server.
   * Put a CA-provided challenge at a DNS location corresponding to the target domain.
   * Receive CA challenge at a (hopefully) administrator-controlled e-mail address corresponding to the domain and then respond to it on the CA's web page.
* Download the issued certificate and install it on their Web Server.

With the exception of the CSR itself and the certificates that are issued, these are all completely ad hoc procedures and are accomplished by getting the human user to follow interactive natural-language instructions from the CA rather than by machine-implemented published protocols.  In many cases, the instructions are difficult to follow and cause significant confusion.  Informal usability tests by the authors indicate that webmasters often need 1-3 hours to obtain and install a certificate for a domain.  Even in the best case, the lack of published, standardized mechanisms presents an obstacle to the wide deployment of HTTPS and other PKIX-dependent systems because it inhibits mechanization of tasks related to certificate issuance, deployment, and revocation.

This document describes an extensible framework for automating the issuance and domain validation procedure, thereby allowing servers and infrastructural software to obtain certificates without user interaction.  Use of this protocol should radically simplify the deployment of HTTPS and the practicality of PKIX authentication for other protocols based on TLS {{RFC5246}}.

# Deployment Model and Operator Experience

The major guiding use case for ACME is obtaining certificates for Web sites (HTTPS {{RFC2818}}).  In that case, the server is intended to speak for one or more domains, and the process of certificate issuance is intended to verify that the server actually speaks for the domain.

Different types of certificates reflect different kinds of CA verification of information about the certificate subject.  "Domain Validation" (DV) certificates are by far the most common type.  For DV validation, the CA merely verifies that the requester has effective control of the web server and/or DNS server for the domain, but does not explicitly attempt to verify their real-world identity.  (This is as opposed to "Organization Validation" (OV) and "Extended Validation" (EV) certificates, where the process is intended to also verify the real-world identity of the requester.)

DV certificate validation commonly checks claims about properties related to control of a domain name -- properties that can be observed by the issuing authority in an interactive process that can be conducted purely online.  That means that under typical circumstances, all steps in the request, verification, and issuance process can be represented and performed by Internet protocols with no out-of-band human intervention.

When an operator deploys a current HTTPS server, it generally prompts him to generate a self-signed certificate.  When an operator deploys an ACME-compatible web server, the experience would be something like this:

* The ACME client prompts the operator for the intended domain name(s)
  that the web server is to stand for.
* The ACME client presents the operator with a list of CAs from which it could
  get a certificate.  
  (This list will change over time based on the capabilities of CAs and updates to ACME configuration.)
  The ACME client might prompt the operator for
  payment information at this point.
* The operator selects a CA.
* In the background, the ACME client contacts the CA and requests that
  a certificate be issued for the intended domain name(s).
* Once the CA is satisfied, the certificate is issued and the ACME client
  automatically downloads and installs it, potentially notifying the
  operator via e-mail, SMS, etc.
* The ACME client periodically contacts the CA to get updated
  certificates, stapled OCSP responses, or whatever else would be
  required to keep the server functional and its credentials up-to-date.

The overall idea is that it's nearly as easy to deploy with a CA-issued certificate as a self-signed certificate, and that once the operator has done so, the process is self-sustaining with minimal manual intervention.  Close integration of ACME with HTTPS servers, for example, can allow the immediate and automated deployment of certificates as they are issued, optionally sparing the human administrator from additional configuration work.


# Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 {{RFC2119}}.

The two main roles in ACME are “client” and “server”.  The ACME client uses the protocol to request certificate management actions, such as issuance or revocation.  An ACME client therefore typically runs on a web server, mail server, or some other server system which requires valid TLS certificates.  The ACME server runs at a certificate authority, and responds to client requests, performing the requested actions if the client is authorized.

For simplicity, in the HTTPS transactions used by ACME, the ACME client is the HTTPS client and the ACME server is the HTTPS server.

In the discussion below, we will refer to three different types of keys / key pairs:

Subject Public Key:
: A public key to be included in a certificate.

Account Key Pair:
: A key pair for which the ACME server considers the holder of the private key authorized to manage certificates for a given identifier.  The same key pair may be authorized for multiple identifiers.

Recovery Token:
: A secret value that can be used to associate a new account key pair with a registration, in the event that the private key of the old account key pair is lost.

ACME messaging is based on HTTPS {{RFC2818}} and JSON {{RFC7159}}.  Since JSON is a text-based format, binary fields are Base64-encoded.  For Base64 encoding, we use the variant defined in {{I-D.ietf-jose-json-web-signature}}.  The important features of this encoding are (1) that it uses the URL-safe character set, and (2) that "=" padding characters are stripped.

Some HTTPS bodies in ACME are authenticated and integrity-protected by being encapsulated in a JSON Web Signature (JWS) object {{I-D.ietf-jose-json-web-signature}}.  ACME uses a profile of JWS, with the following restrictions:

* The JWS MUST use the JSON or Flattened JSON Serialization
* If the JWS is in the JSON Serialization, it MUST NOT include more than one signature in the "signatures" array
* The JWS Header MUST include "alg" and "jwk" fields


# Protocol Overview

ACME allows a client to request certificate management actions using a set of JSON messages carried over HTTPS.   In some ways, ACME functions much like a traditional CA, in which a user creates an account, adds identifiers to that account (proving control of the domains), and requests certificate issuance for those domains while logged in to the account.  

In ACME, the account is represented by an account key pair.  The "add a domain" function is accomplished by authorizing the key pair for a given domain.  Certificate issuance and revocation are authorized by a signature with the key pair.

The first phase of ACME is for the client to register with the ACME server.  The client generates an asymmetric key pair and associates this key pair with a set of contact information by signing the contact information.  The server acknowledges the registration by replying with a recovery token that the client can provide later to associate a new account key pair in the event that the first account key pair is lost.

~~~~~~~~~~

      Client                                                  Server

      Contact Information
      Signature                     ------->

                                    <-------          Recovery Token

~~~~~~~~~~

Before a client can issue certificates, it must establish an authorization with the server for an account key pair to act for the identifier(s) that it wishes to include in the certificate.  To do this, the client must demonstrate to the server both (1) that it holds the private key of the account key pair, and (2) that it has authority over the identifier being claimed.

Proof of possession of the account key is built into the ACME protocol.  All messages from the client to the server are signed by the client, and the server verifies them using the public key of the account key pair.

To verify that the client controls the identifier being claimed, the server issues the client a set of challenges.  Because there are many different ways to validate possession of different types of identifiers, the server will choose from an extensible set of challenges that are appropriate for the identifier being claimed.  The client responds with a set of responses that tell the server which challenges the client has completed.  The server then validates the challenges to check that the client has accomplished the challenge.

For example, if the client requests a domain name, the server might challenge the client to provision a record in the DNS under that name, or to provision a file on a web server referenced by an A or AAAA record under that name.  The server would then query the DNS for the record in question, or send an HTTP request for the file.  If the client provisioned the DNS or the web server as expected, then the server considers the client authorized for the domain name.

~~~~~~~~~~

      Client                                                  Server

      Identifier
      Signature                     ------->

                                    <-------              Challenges

      Responses
      Signature                     ------->

                                    <-------       Updated Challenge

      Poll                          ------->

                                    <-------           Authorization

~~~~~~~~~~

Once the client has authorized an account key pair for an identifier, it can use the key pair to authorize the issuance of certificates for the identifier.  To do this, the client sends a PKCS#10 Certificate Signing Request (CSR) to the server (indicating the identifier(s) to be included in the issued certificate), a set of links to any required authorizations, and a signature over the CSR by the private key of the account key pair.

If the server agrees to issue the certificate, then it creates the certificate and provides it in its response.  The certificate is assigned a URI, which the client can use to fetch updated versions of the certificate.

~~~~~~~~~~

      Client                                                 Server

      CSR
      Authorization URI(s)
      Signature                    -------->

                                   <--------            Certificate

~~~~~~~~~~

To revoke a certificate, the client simply sends a revocation request, signed with an authorized key pair, and the server indicates whether the request has succeeded.

~~~~~~~~~~

      Client                                                 Server

      Revocation request
      Signature                    -------->

                                   <--------                 Result

~~~~~~~~~~


Note that while ACME is defined with enough flexibility to handle different types of identifiers in principle, the primary use case addressed by this document is the case where domain names are used as identifiers.  For example, all of the identifier validation challenges described in Section {identifier-validation-challenges} below address validation of domain names.  The use of ACME for other protocols will require further specification, in order to describe how these identifiers are encoded in the protocol, and what types of validation challenges the server might require.


# Certificate Management

In this section, we describe the certificate management functions that ACME enables:

  * Registration
  * Key Authorization
  * Certificate Issuance
  * Certificate Revocation

Each of these functions is accomplished by the client sending a sequence of HTTPS requests to the server, carrying JSON messages.  Each subsection below describes the message formats used by the function, and the order in which messages are sent.

## Resources and Requests

ACME is structured as a REST application with a few types of resources:

* Registration resources, representing information about an account
* Authorization resources, representing an account's authorization to act for an identifier
* Challenge resources, representing a challenge to prove control of an identifier
* Certificate resources, representing issued certificates
* A "new-registration" resource
* A "new-authorization" resource
* A "new-certificate" resource

In general, the intent is for authorization and certificate resources to contain only public information, so that CAs may publish these resources to document what certificates have been issued and how they were authorized.  Non-public information, such as
contact information, is stored in registration resources.

In order to accomplish ACME transactions, a client needs to have the server's new-registration, new-authorization, and new-certificate URIs; the remaining URIs are provided to the client as a result of requests to these URIs.  To simplify
configuration, ACME uses the "next" link relation to indicate URI to contact for the next step in processing: From registration to authorization, and from authorization to certificate issuance.  In this way, a client need only be configured with the registration URI.

The "up" link relation is used with challenge resources to indicate the authorization resource to which a challenge belongs.  It is also used from certificate resources to indicate a resource from which the client may fetch a chain of CA certificates that could be used to validate the certificate in the original resource.

The following diagram illustrates the relations between resources on an ACME server.  The solid lines indicate link relations, and the dotted lines correspond to relationships expressed in other ways, e.g., the Location header in a 201 (Created) response.

~~~~~~~~~~
             "next"              "next"
    new-reg ---+----> new-authz ---+----> new-cert    cert-chain
       .       |          .        |         .            ^
       .       |          .        |         .            | "up"
       V       |          V        |         V            |
      reg* ----+        authz -----+       cert-----------+
                         . ^
                         . | "up"
                         V |
                       challenge

~~~~~~~~~~


The remainder of this section provides the details of how these resources are structured and how the ACME protocol makes use of them.

All ACME requests with a non-empty body MUST encapsulate the body in a JWS object, signed using the account key pair.  The server MUST verify the JWS before processing the request.  (For readability, however, the examples below omit this encapsulation.)  Encapsulating request bodies in JWS provides a simple authentication of requests by way of key continuity.

Note that this implies that GET requests are not authenticated.  Servers MUST NOT respond to GET requests for resources that might be considered sensitive.

The following table illustrates a typical sequence of requests required to establish a new account with the server, prove control of an identifier, issue a certificate, and fetch an updated certificate some time after issuance.  The "->" is a mnemonic for
 a Location header pointing to a created resource.

| Action             | Request        | Response     |
|:-------------------|:---------------|:-------------|
| Register           | POST new-reg   | 201 -> reg   |
| Request challenges | POST new-authz | 201 -> authz |
| Answer challenges  | POST challenge | 200          |
| Poll for status    | GET  authz     | 200          |
| Request issuance   | POST new-cert  | 201 -> cert  |
| Check for new cert | GET  cert      | 200          |


## Errors

Errors can be reported in ACME both at the HTTP layer and within ACME payloads.  ACME servers can return responses with an HTTP error response code (4XX or 5XX).  For example:  If the client submits a request using a method not allowed in this document, then the server MAY return status code 405 (Method Not Allowed).

When the server responds with an error status, it SHOULD provide additional information using problem document {{I-D.ietf-appsawg-http-problem}}.  The "type" and "detail" fields MUST be populated.  To facilitate automatic response to errors, this document defines the following standard tokens for use in the "type" field (within the "urn:acme:" namespace):

| Code            | Semantic                                                 |
|:----------------|:---------------------------------------------------------|
| malformed       | The request message was malformed                        |
| unauthorized    | The client lacks sufficient authorization                |
| serverInternal  | The server experienced an internal error                 |
| badCSR          | The CSR is unacceptable (e.g., due to a short key)       |

Authorization and challenge objects can also contain error information to indicate why the server was unable to validate authorization.

TODO: Flesh out errors and syntax for them

## Registration

An ACME registration resource represents a set of metadata associated to an account key pair.  Registration resources have the following structure:

key (required, dictionary):
: The public key of the account key pair, encoded as a JSON Web Key object {{I-D.ietf-jose-json-web-key}}.

contact (optional, array of string):
: An array of URIs that the server can use to contact the client for issues related to this authorization. For example, the server may wish to notify the client about server-initiated revocation.

recoveryToken (optional, string):
: An opaque token that the client can present to demonstrate that it participated in a prior authorization transaction.

agreement (optional, string):
: A URI referring to a subscriber agreement or terms of service provided by the server (see below).  Including this field indicates the client's agreement with these terms.

A client creates a new account with the server by sending a POST request to the server's new-registration URI.  In most cases (except for account recovery, below), the body of the request is a registration object containing only the "contact" field.


~~~~~~~~~~

POST /acme/new-registration HTTP/1.1
Host: example.com

{
  "contact": [
    "mailto:cert-admin@example.com",
    "tel:+12025551212"
  ],
}
/* Signed as JWS */

~~~~~~~~~~

The server MUST ignore any values provided in the "key" field in registration bodies sent by the client, as well as any other fields that it does not recognize.  If new fields are specified in the future, the specification of those fields MUST describe whether they may be provided by the client.

The server creates a registration object with the included contact information.  The "key" element of the registration is set to the public key used to verify the JWS (i.e., the "jwk" element of the JWS header).  The server also provides a random
recovery token.  The server returns this registration object in a 201 (Created) response, with the registration URI in a Location header field.  The server MUST also indicate its new-authorization URI using the "next" link relation.

If the server wishes to present the client with terms under which the ACME service is to be used, it may indicate the URI where such terms can be accessed in a Link header with link relation "terms-of-service".  As noted above, the client may indicate its
agreement with these terms by updating its registration to include the "agreement" field, with the terms URI as its value.

~~~~~~~~~~

HTTP/1.1 201 Created
Content-Type: application/json
Location: https://example.com/reg/asdf
Link: <https://example.com/acme/new-authz>;rel="next"
Link: <https://example.com/acme/terms>;rel="terms-of-service"

{
  "key": { /* JWK from JWS header */ },

  "contact": [
    "mailto:cert-admin@example.com",
    "tel:+12025551212"
  ],

  "recoveryToken": "uV2Aph7-sghuCcFVmvsiZw"
}

~~~~~~~~~~

If the client wishes to update this information in the future, it sends a POST request with updated information to the registration URI.  The server MUST ignore any updates to the "key" or "recoveryToken" fields, and MUST verify that the request is signed
with the private key corresponding to the "key" field of the request before updating the registration.

Servers SHOULD NOT respond to GET requests for registration resources as these requests are not authenticated.


### Account Recovery

Once a client has created an account with an ACME server, it is possible that the private key for the account will be lost.  The recovery token included in the registration allows the client to recover from this situtation, as long as it still has the recovery token.

A client may ask to associate a new key pair with its account by including the recovery token in its new-registration request.  If a server receives such a request with a recovery token corresponding to a known account, then it MUST replace the public key in the old registration (corresponding to the recovery token) with the JWK used to sign the recovery request.  The server MUST consider the old public key to be no longer valid for this account.

{::comment}
TODO: Re-add recoveryContact here https://github.com/letsencrypt/acme-spec/issues/136
{:/comment}

Client implementers should note that recovery tokens are very powerful.  If they are exposed to unauthorized parties, then that party will be able to hijack the corresponding account, enabling it to issue certificates under any authorizations on the account.  Improper use of a recovery token can cause legitimate account keys to be invalidate.  Client implementations should thus provide adequate safeguards around storage and use of recovery tokens.


## Authorization Resources

An ACME authorization resource represents server's authorization for an account
to represent an identifier.  In addition to the identifier, an
authorization includes several metadata fields, such as the status of the
authorization (e.g., "pending", "valid", or "revoked") and which challenges were
used to validate possession of the identifier.

The structure of an ACME authorization resource is as follows:

identifier (required, dictionary of string):
: The identifier that the account is authorized to represent

  type (required, string):
  : The type of identifier.

  value (required, string):
  : The identifier itself.

status (optional, string):
: The status of this authorization.  Possible values are: "unknown", "pending", "processing", "valid", "invalid" and "revoked".  If this field is missing, then the default value is "pending".

expires (optional, string):
: The date after which the server will consider this authorization invalid, encoded in the format specified in RFC 3339 {{RFC3339}}.

challenges (required, array):
: The challenges that the client needs to fulfill in order to prove possession of the identifier (for pending authorizations).  For final authorizations, the challenges that were used.  Each array entry is a dictionary with parameters required to validate the challenge, as specified in Section {identifier-validation-challenges}.

combinations (optional, array of arrays of integers):
: A collection of sets of challenges, each of which would be sufficient to prove possession of the identifier. Clients complete a set of challenges that that covers at least one set in this array. Challenges are identified by their indices in the challenges array.  If no "combinations" element is included in an authorization object, the client completes all challenges.


The only type of identifier defined by this specification is a fully-qualified domain name (type: "dns").  The value of the identifier MUST be the ASCII representation of the domain name.

~~~~~~~~~~

{
  "status": "valid",
  "expires": "2015-03-01",

  "identifier": {
    "type": "dns",
    "value": "example.org"
  },

  "challenges": [
    {
      "type": "simpleHttps",
      "status": "valid",
      "validated": "2014-12-01T12:05Z",
      "token": "IlirfxKKXAsHtmzK29Pj8A"
      "path": "Hf5GrX4Q7EBax9hc2jJnfw"
    }
  ],
}

~~~~~~~~~~


## Identifier Authorization

The identifier authorization process establishes the authorization of an account
to manage certificates for a given identifier.  This process must assure the
server of two things: First, that the client controls the private key of the
account key pair, and second, that the client holds the identifier in question.
This process may be repeated to associate multiple identifiers to a key pair
(e.g., to request certificates with multiple identifiers), or to associate
multiple accounts with an identifier (e.g., to allow multiple entities to
manage certificates).

As illustrated by the figure in the overview section above, the authorization process proceeds in two phases.  The client first requests a new authorization, and then the server issues challenges that the client responds to.

To begin the key authorization process, the client sends a POST request to the server's new-authorization resource.  The body of the POST request MUST contain a JWS object, whose payload is a partial authorization object.  This JWS object MUST contain only the "identifier" field, so that the server knows what identifier is being authorized.

The authorization object is implicitly tied to the account key used to sign the
request. Once created, the authorization may only be updated and referenced by
that account.

~~~~~~~~~~

POST /acme/new-authorization HTTP/1.1
Host: example.com

{
  "identifier": {
    "type": "dns",
    "value": "example.org"
  }
}
/* Signed as JWS */

~~~~~~~~~~

Before processing the authorization further, the server SHOULD determine whether it is willing to issue certificates for the identifier.  For example, the server should check that the identifier is of a supported type.  Servers might also check names against a blacklist of known high-value identifiers.  If the server is unwilling to issue for the identifier, it SHOULD return a 403 (Forbidden) error, with a problem document describing the reason for the rejection.

If the server is willing to proceed, it builds a pending authorization object from the initial authorization object submitted by the client.

* "identifier" the identifier submitted by the client.
* "status": SHOULD be "pending" (MAY be omitted)
* "challenges" and "combinations": As selected by the server's policy for this identifier
* The "expires" field MUST be absent.

The server allocates a new URI for this authorization, and returns a 201 (Created) response, with the authorization URI in a Location header field, and the JSON authorization object in the body.

~~~~~~~~~~

HTTP/1.1 201 Created
Content-Type: application/json
Location: https://example.com/authz/asdf
Link: <https://example.com/acme/new-cert>;rel="next"

{
  "status": "pending",

  "identifier": {
    "type": "dns",
    "value": "example.org"
  },

  "challenges": [
    {
      "type": "simpleHttps",
      "uri": "https://example.com/authz/asdf/0",
      "token": "IlirfxKKXAsHtmzK29Pj8A"
    },
    {
      "type": "dns",
      "uri": "https://example.com/authz/asdf/1"
      "token": "DGyRejmCefe7v4NfDGDKfA"
    }
  },

  "combinations": [ 
    [0, 2],
    [1, 2]
  ]
}

~~~~~~~~~~

The client needs to respond with information to complete the challenges.  To do this, the client updates the authorization object received from the server by filling in any required information in the elements of the "challenges" dictionary.  For example, if the client wishes to complete the "simpleHttps" challenge, it needs to provide the "path" component.  (This is also the stage where the client should perform any actions required by the challenge.)

The client sends these updates back to the server in the form of a JSON object with the response fields required by the challenge type, carried in a POST request to the challenge URI (not authorization URI or the new-authorization URI).  This allows the client to send information only for challenges it is responding to.

For example, if the client were to respond to the "simpleHttps" challenge in the above authorization, it would send the following request:

~~~~~~~~~~

POST /acme/authz/asdf/0 HTTP/1.1
Host: example.com

{
  "path": "Hf5GrX4Q7EBax9hc2jJnfw"
}
/* Signed as JWS */

~~~~~~~~~~

The server updates the authorization document by updating its representation of the challenge with the response fields provided by the client.  The server MUST ignore any fields in the response object that are not specified as response fields for this type of challenge.  The server provides a 200 response including the updated challenge.

Presumably, the client's responses provide the server with enough information to validate one or more challenges.  The server is said to "finalize" the authorization when it has completed all the validations it is going to complete, and assigns the authorization a status of "valid" or "invalid", corresponding to whether it considers the account authorized for the identifier.  If the final state is "valid", the server MUST add an "expires" field to the authorization.  When finalizing an authorization, the server MAY remove the "combinations" field (if present) or remove any unfulfilled challenges.

Usually, the validation process will take some time, so the client will need to poll the authorization resource to see when it is finalized.  For challenges where the client can tell when the server has validated the challenge (e.g., by seeing an HTTP or DNS request from the server), the client SHOULD NOT begin polling until it has seen the validation request from the server.

To check on the status of an authorization, the client sends a GET request to the authorization URI, and the server responds with the current  authorization object.  To provide some degree of control over polling, the server MAY provide a Retry-After header field to indicate how long it expect to take in finalizing the response.

~~~~~~~~~~

GET /acme/authz/asdf HTTP/1.1
Host: example.com

HTTP/1.1 200 OK

{
  "status": "valid",
  "expires": "2015-03-01",

  "identifier": {
    "type": "dns",
    "value": "example.org"
  },

  "challenges": [
    {
      "type": "simpleHttps"
      "status": "valid",
      "validated": "2014-12-01T12:05Z",
      "token": "IlirfxKKXAsHtmzK29Pj8A"
      "path": "Hf5GrX4Q7EBax9hc2jJnfw"
    }
  ]
}

~~~~~~~~~~


## Certificate Issuance

The holder of an authorized key pair for an identifier may use ACME to request that a certificate be issued for that identifier.  The client makes this request by sending a POST request to the server's new-certificate resource.  The body of the POST is a JWS object whose JSON payload contains a Certificate Signing Request (CSR) {{RFC2986}} and set of authorization URIs.  The CSR encodes the parameters of the requested certificate; authority to issue is demonstrated by the JWS signature and the linked authorizations.

csr (required, string):
: A CSR encoding the parameters for the certificate being requested.  The CSR is sent in Base64-encoded version of the DER format.  (Note: This field uses the same modified Base64-encoding rules used elsewhere in this document, so it is different from PEM.)

authorizations (required, array of string):
: An array of URIs for authorization resources.

~~~~~~~~~~

POST /acme/new-cert HTTP/1.1
Host: example.com
Accept: application/pkix-cert

{
  "csr": "5jNudRx6Ye4HzKEqT5...FS6aKdZeGsysoCo4H9P",
  "authorizations": [
    "https://example.com/acme/authz/asdf"
  ]
}
/* Signed as JWS */

~~~~~~~~~~

The CSR encodes the client's requests with regard to the content of the certificate to be issued.  The CSR MUST contain at least one extensionRequest attribute {{RFC2985}} requesting a subjectAltName extension, containing the requested identifiers.

The values provided in the CSR are only a request, and are not guaranteed.  The server or CA may alter any fields in the certificate before issuance.  For example, the CA may remove identifiers that are not authorized for the key indicated in the "authorization" field.

If the CA decides to issue a certificate, then the server returns the certificate in a response with status code 201 (Created).  The server MUST indicate a URL for this certificate in a Location header field.

The default format of the certificate is DER (application/pkix-cert).  The client may request other formats by including an Accept header in its request.

The server can provide metadata about the certificate in HTTP headers.  For example, the server can include a Link relation header field {{RFC5988}} with relation "up" to provide a certificate under which this certificate was issued.  Or the server can include an Expires header as a hint to the client about when to re-query to refresh the certificate.  (Of course, the real expiration of the certificate is controlled by the notAfter time in the certificate itself.)

~~~~~~~~~~

HTTP/1.1 201 Created
Content-Type: application/pkix-cert
Link: <https://example.com/acme/ca-cert>;rel="up";title="issuer"
Location: https://example.com/acme/cert/asdf

[DER-encoded certificate]

~~~~~~~~~~

## Certificate Refresh

To refresh the certificate, the client simply sends a GET request to the certificate URL.  This allows the server to provide the client with updated certificates with the same content and different validity intervals, for as long as all of the authorization objects underlying the certificate are valid.

If a client sends a refresh request and the server is not willing to refresh the certificate, the server MUST respond with status code 403 (Forbidden).  If the client still wishes to obtain a certificate, it can re-initiate the authorization process for any expired authorizations related to the certificate.

## Certificate Revocation

To request that a certificate be revoked, the client sends a POST request to
/acme/revoke-cert.  The body of the POST is a JWS object whose JSON payload
contains the certificate to be revoked:

certificate (required, string):
: The DER form of the certificate, Base64-encoded using the JOSE Base64 variant.

~~~~~~~~~~

POST /acme/revoke-cert HTTP/1.1
Host: example.com

{
  "certificate": "MIIEDTCCAvegAwIBAgIRAP8..."
}
/* Signed as JWS */

~~~~~~~~~~

Before revoking a certificate, the server MUST verify at least one of these conditions
applies:
- the public key of the key pair signing the request matches the public key in
  the certificate.
- the key pair signing the request is an account key, and the corresponding
  account is authorized to act for all of the identifier(s) in the certificate.

If the revocation succeeds, the server responds with status code 200 (OK).  If the revocation fails, the server returns an error.

~~~~~~~~~~

HTTP/1.1 200 OK
Content-Length: 0

--- or ---

HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
Content-Language: en

{
  "type": "urn:acme:error:unauthorized"
  "detail": "No authorization provided for name example.net"
  "instance": "http://example.com/doc/unauthorized"
}

~~~~~~~~~~


# Identifier Validation Challenges

There are few types of identifier in the world for which there is a standardized mechanism to prove possession of a given identifier.  In all practical cases, CAs rely on a variety of means to test whether an entity applying for a certificate with a given identifier actually controls that identifier.

To accommodate this reality, ACME includes an extensible challenge/response framework for identifier validation.  This section describes an initial set of Challenge types.  Each challenge must describe:

* Content of Challenge payloads (in Challenge messages)
* Content of Response payloads (in authorizationRequest messages)
* How the server uses the Challenge and Response to verify control of an identifier

The only general requirement for Challenge and Response payloads is that they MUST be structured as a JSON object, and they MUST contain a parameter "type" that specifies the type of Challenge or Response encoded in the object.

Different challenges allow the server to obtain proof of different aspects of control over an identifier.  In some challenges, like Simple HTTPS and DVSNI, the client directly proves control of an identifier.  In other challenges, such as Proof of Possession, the client proves historical control of the identifier, by reference to a prior authorization transaction or certificate.

The choice of which Challenges to offer to a client under which circumstances is a matter of server policy.  A server may choose different sets of challenges depending on whether it has interacted with a domain before, and how.  For example:

| Domain status                                 | Challenges typically sufficient for (re)Authorization |
|:----------------------------------------------|:------------------------------------------------------|
| No known prior certificates or ACME usage     | Domain Validation (DVSNI or Simple HTTPS)             |
| Existing valid certs, first use of ACME       | DV + Proof of Possession of previous CA-signed key    |
| Ongoing ACME usage                            | PoP of previous Authorized key                        |
| Ongoing ACME usage, lost Authorized key       | DV + PoP of ACME-certified Subject key                |
| ACME usage, all keys and recovery tokens lost | Proof of legal identity of the site owner             |

The identifier validation challenges described in this section all relate to validation of domain names.  If ACME is extended in the future to support other types of identifier, there will need to be new Challenge types, and they will need to specify which types of identifier they apply to.

## Simple HTTPS

With Simple HTTPS validation, the client in an ACME transaction proves its control over a domain name by proving that it can provision resources on an HTTPS server that responds for that domain name.  The ACME server challenges the client to provision a file with a specific string as its contents.

As a domain may resolve to multiple IPv4 and IPv6 addresses, the server will connect to at least one of the hosts found in A and AAAA records, at its discretion.  Simple HTTPS validation of IPv6-only domains may not be supported by all servers.

type (required, string):
: The string "simpleHttps"

token (required, string):
: The value to be provisioned in the file.  This value MUST have at least 128 bits of entropy, in order to prevent an attacker from guessing it.  It MUST NOT contain any non-ASCII characters.

~~~~~~~~~~

{
  "type": "simpleHttps",
  "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA"
}

~~~~~~~~~~

A client responds to this Challenge by provisioning the nonce as a resource on the HTTPS server for the domain in question.  The path at which the resource is provisioned is determined by the client, but MUST begin with ".well-known/acme-challenge/".  The content type of the resource MUST be "text/plain".  The client returns the part of the path coming after that prefix in its Response message.

type (required, string):
: The string "simpleHttps"

path (required, string):
: The string to be appended to the standard prefix ".well-known/acme-challenge/" in order to form the path at which the nonce resource is provisioned.  The result of concatenating the prefix with this value MUST match the "path" production in the standard URI format {{RFC3986}}

~~~~~~~~~~

{
  "type": "simpleHttps",
  "path": "6tbIMBC5Anhl5bOlWT5ZFA"
}

~~~~~~~~~~

Given a Challenge/Response pair, the server verifies the client's control of the domain by verifying that the resource was provisioned as expected.

1. Form a URI by populating the URI template "https://{domain}/.well-known/acme-challenge/{path}", where the domain field is set to the domain name being verified and the path field is the path provided in the challenge {{RFC6570}}.
2. Verify that the resulting URI is well-formed.
3. Dereference the URI using an HTTPS GET request.
4. Verify that the certificate presented by the HTTPS server is a valid self-signed certificate, and contains the domain name being validated as well as the public key of the key pair being authorized.
5. Verify that the Content-Type header of the response is either absent, or has the value "text/plain"
6. Compare the entity body of the response with the nonce.  This comparison MUST be performed in terms of Unicode code points, taking into account the encodings of the stored nonce and the body of the request.

If the GET request succeeds and the entity body is equal to the nonce, then the validation is successful.  If the request fails, or the body does not match the nonce, then it has failed.


## Domain Validation with Server Name Indication

The Domain Validation with Server Name Indication (DVSNI) validation method aims to ensure that the ACME client has administrative access to the web server at the domain name being validated, and possession of the private key being authorized.  The ACME server verifies that the operator can reconfigure the web server by having the client create a new self-signed challenge certificate and respond to TLS connections from the ACME server with it.

The challenge proceeds as follows: The ACME server sends the client a random value R and a nonce used to identify the transaction.  The client responds with another random value S.  The server initiates a TLS connection on port 443 to one or more of the IPv4 or IPv6 hosts with the domain name being validated.  In the handshake, the ACME server sets the Server Name Indication extension set to "\<nonce\>.acme.invalid".  The TLS server (i.e., the ACME client) should respond with a valid self-signed certificate containing both the domain name being validated and the domain name "\<Z\>.acme.invalid", where Z = SHA-256(R &#124;&#124; S).

The ACME server's Challenge provides its random value R, and a random nonce used to identify the transaction:

type (required, string):
: The string "dvsni"

r (required, string):
: A random 32-byte octet, Base64-encoded

nonce (required, string):
: A random 16-byte octet string, hex-encoded (so that it can be used as a DNS label)

~~~~~~~~~~

{
  "type": "dvsni",
  "r": "Tyq0La3slT7tqQ0wlOiXnCY2vyez7Zo5blgPJ1xt5xI",
  "nonce": "a82d5ff8ef740d12881f6d3c2277ab2e"
}

~~~~~~~~~~

The client responds to this Challenge by configuring a TLS server on port 443 of a server with the domain name being validated:

1. Decode the server's random value R
2. Generate a random 32-byte octet string S
3. Compute Z = SHA-256(R &#124;&#124; S) (where &#124;&#124; denotes concatenation of octet strings)
4. Generate a self-signed certificate with a subjectAltName extension containing two dNSName values:
  1. The domain name being validated
  2. A name formed by hex-encoding Z and appending the suffix ".acme.invalid"
5. Compute a nonce domain name by appending the suffix ".acme.invalid" to the nonce provided by the server.
6. Configure the TLS server such that when a client presents the nonce domain name in the SNI field, the server presents the generated certificate.

The client's response provides its random value S:

type (required, string):
: The string "dvsni"

s (required, string):
: A random 32-byte secret octet string, Base64-encoded

~~~~~~~~~~

{
  "type": "dvsni",
  "s": "9dbjsl3gTAtOnEtKFEmhS6Mj-ajNjDcOmRkp3Lfzm3c"
}

~~~~~~~~~~

Given a Challenge/Response pair, the ACME server verifies the client's control of the domain by verifying that the TLS server was configured as expected:

1. Compute the value Z = SHA-256(R &#124;&#124; S)
2. Open a TLS connection to the domain name being validated on port 443, presenting the value "\<nonce\>.acme.invalid" in the SNI field.
3. Verify the following properties of the certificate provided by the TLS server:
  * It is a valid self-signed certificate
  * The public key is the public key for the key pair being authorized
  * It contains the domain name being validated as a subjectAltName
  * It contains a subjectAltName matching the hex-encoding of Z, with the suffix ".acme.invalid"

It is RECOMMENDED that the ACME server verify the challenge certificate using multi-path probing techniques to reduce the risk of DNS hijacking attacks.

If the server presents a certificate matching all of the above criteria, then the validation is successful.  Otherwise, the validation fails.


## Proof of Possession of a Prior Key

The Proof of Possession challenge verifies that a client possesses a private key corresponding to a server-specified public key, as demonstrated by its ability to correctly sign server-provided data with that key.

This method is useful if a server policy calls for issuing a certificate only to an entity that already possesses the subject private key of a particular prior related certificate (perhaps issued by a different CA).  It may also help enable other kinds of server policy that are related to authenticating a client's identity using digital signatures.

This challenge proceeds in much the same way as the proof of possession of the authorized key pair in the main ACME flow (challenge + authorizationRequest).  The server provides a nonce and the client signs over the nonce.  The main difference is that rather than signing with the private key of the key pair being authorized, the client signs with a private key specified by the server.  The server can specify which key pair(s) are acceptable directly (by indicating a public key), or by asking for the key corresponding to a certificate.

The server provides the following fields as part of the challenge:

type (required, string):
: The string "proofOfPossession"

alg (required, string):
: A token indicating the cryptographic algorithm that should be used by the client to compute the signature {{I-D.ietf-jose-json-web-algorithms}}.  (MAC algorithms such as "HS*" MUST NOT be used.)  The client MUST verify that this algorithm is supported for the indicated key before responding to this challenge.

nonce (required, string):
: A random 16-byte octet string, Base64-encoded

hints (required, object):
: A JSON object that contains various clues for the client about what the requested key is, such that the client can find it.  Entries in the hints object may include:

jwk (required, object):
: A JSON Web Key object describing the public key whose corresponding private key should be used to generate the signature {{I-D.ietf-jose-json-web-key}}

certFingerprints (optional, array):
: An array of certificate fingerprints, hex-encoded SHA1 hashes of DER-encoded certificates that are known to contain this key

certs (optional, array):
: An array of certificates, in Base64-encoded DER format, that contain acceptable public keys.

subjectKeyIdentifiers (optional, array):
: An array of hex-encoded Subject Key Identifiers (SKIDs) from certificate(s) that contain the key.  Because of divergences in the way that SKIDs are calculated {{RFC5280}}, there may conceivably be more than one of these.

serialNumbers (optional, array of numbers):
: An array of serial numbers of certificates that are known to contain the requested key

issuers (optional, array):
: An array of X.509 Distinguished Names {{RFC5280}} of CAs that have been observed to issue certificates for this key, in text form {{RFC4514}}

authorizedFor (optional, array):
: An array of domain names, if any, for which this server regards the key as an ACME Authorized key.

~~~~~~~~~~

{
  "type": "proofOfPossession",
  "alg": "RS256",
  "nonce": "eET5udtV7aoX8Xl8gYiZIA",
  "hints" : {
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "n": "KxITJ0rNlfDMAtfDr8eAw...fSSoehDFNZKQKzTZPtQ"
    },
    "certFingerprints": [
      "93416768eb85e33adc4277f4c9acd63e7418fcfe",
      "16d95b7b63f1972b980b14c20291f3c0d1855d95",
      "48b46570d9fc6358108af43ad1649484def0debf"
    ],
    "subjectKeyIdentifiers":  [
      "d0083162dcc4c8a23ecb8aecbd86120e56fd24e5"
    ],
    "serialNumbers": [34234239832, 23993939911, 17],
    "issuers": [
      "C=US, O=SuperT LLC, CN=SuperTrustworthy Public CA",
      "O=LessTrustworthy CA Inc, CN=LessTrustworthy But StillSecure"
    ],
    "authorizedFor": ["www.example.com", "example.net"]
  }
}

~~~~~~~~~~

In this case the server is challenging the client to prove its control over the private key that corresponds to the public key specified in the jwk object.  The signing algorithm is specified by the alg field.  The nonce value is used by the server to identify this challenge and is also used, also with a client-provided signature nonce, as part of the signature input.

~~~~~~~~~~

      signature-input = signature-nonce || server-nonce

~~~~~~~~~~

The client's response includes the server-provided nonce, together with a signature over that nonce by one of the private keys requested by the server.

type (required, string):
: The string "proofOfPossession"

nonce (required, string):
: The server nonce that the server previously associated with this challenge

signature (required, object):
: The ACME signature computed over the signature-input using the server-specified algorithm


~~~~~~~~~~

{
  "type": "proofOfPossession",
  "nonce": "eET5udtV7aoX8Xl8gYiZIA",
  "signature": {
    "alg": "RS256",
    "nonce": "eET5udtV7aoX8Xl8gYiZIA",
    "sig": "KxITJ0rNlfDMAtfDr8eAw...fSSoehDFNZKQKzTZPtQ",
    "jwk": {
      "kty": "RSA",
      "e": "AQAB",
      "n": "KxITJ0rNlfDMAtfDr8eAw...fSSoehDFNZKQKzTZPtQ"
    }
  }
}

~~~~~~~~~~

Note that just as in the authorizationRequest message, there are two nonces here, once provided by the client (inside the signature object) and one provided by the server in its challenge (outside the signature object).  The signature covers the concatenation of these two nonces (as specified in the signature-input above).

If the server is able to validate the signature and confirm that the jwk and alg objects are unchanged from the original challenge, the server can conclude that the client is in control of the private key that corresponds to the specified public key.  The server can use this evidence in support of its authorization and certificate issuance policies.


## DNS

When the identifier being validated is a domain name, the client can prove control of that domain by provisioning records under it.   The DNS challenge requires the client to provision a TXT record containing a validation token under a specific validation domain name.

type (required, string):
: The string "dns"

token (required, string):
: An ASCII string that is to be provisioned in the TXT record.  This string SHOULD be randomly generated, with at least 128 bits of entropy (e.g., a hex-encoded random octet string).

~~~~~~~~~~

{
  "type": "dns",
  "token": "17817c66b60ce2e4012dfad92657527a"
}

~~~~~~~~~~

In response to this challenge, the client first MUST verify that the token contains only ASCII characters.  If so, the client constructs the validation domain name by appending the label "_acme-challenge" to the domain name being validated.  For example, if the domain name being validated is "example.com", then the client would provision the following DNS record:

~~~~~~~~~~

_acme-challenge.example.com. IN TXT "17817c66b60ce2e4012dfad92657527a"

~~~~~~~~~~

The response to a DNS challenge is simply an acknowledgement that the relevant record has been provisioned.

type (required, string):
: The string "dns"

~~~~~~~~~~

{
  "type": "dns"
}

~~~~~~~~~~

To validate a DNS challenge, the server queries for TXT records under the validation domain name.  If it receives a record whose contents match the token in the challenge, then the validation succeeds.  Otherwise, the validation fails.


## Other possibilities

For future work:

* Email
* DNSSEC
* WHOIS

# IANA Considerations

TODO

* Register .well-known path
* Create identifier validation method registry
* Registries of syntax tokens, e.g., message types / error types?

# Security Considerations

TODO

* General authorization story
* PoP nonce entropy
* ToC/ToU; duration of key authorization
* Clients need to protect recovery token
* CA needs to perform a very wide range of issuance policy enforcement and sanity-check steps
* Parser safety (for JSON, JWK, ASN.1, and any other formats that can be parsed by the ACME server)


# Acknowledgements

This document draws on many concepts established by Eric Rescorla's "Automated Certificate Issuance Protocol" draft.  Martin Thomson provided helpful guidance in the use of HTTP.
