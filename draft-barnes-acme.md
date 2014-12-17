---
title: "Automatic Certificate Management Environment (ACME)"
abbrev: ACME
docname: draft-barnes-acme-00
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
    ins: E. Rescorla
    name: Eric Rescorla
    org: Mozilla
    email: ekr@rtfm.com
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
  RFC6570:
  RFC7159:
  RFC7386:
  I-D.ietf-jose-json-web-key:
  I-D.ietf-jose-json-web-algorithms:
  I-D.ietf-jose-json-web-signature:
  I-D.ietf-appsawg-http-problem:

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

This document describes an extensible framework for automating the issuance and domain validation procedure, thereby allowing servers and infrastructural software to obtain certificates without user interaction.  Use of this protocol should radically simplify the deployment of HTTPS and the practicality of PKIX authentication for other TLS based protocols.

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
: A secret value that can be used to demonstrate prior authorization for an identifier, in a situation where all Subject Private Keys and Account Keys are lost.

ACME messaging is based on HTTPS {{RFC2818}} and JSON {{RFC7159}}.  Since JSON is a text-based format, binary fields are Base64-encoded.  For Base64 encoding, we use the variant defined in {{I-D.ietf-jose-json-web-signature}}.  The important features of this encoding are (1) that it uses the URL-safe character set, and (2) that "=" padding characters are stripped.

Some HTTPS bodies in ACME are authenticated and integrity-protected by being encapsulated in a JSON Web Signature (JWS) object {{I-D.ietf-jose-json-web-signature}}.  ACME uses a profile of JWS, with the following restrictions:

* The JWS MUST use the Flattened JSON Serialization
* The JWS Header MUST include "alg" and "jwk" fields

# Protocol Overview

ACME allows a client to request certificate management actions using a set of JSON messages carried over HTTPS.   In some ways, ACME functions much like a traditional CA, in which a user creates an account, adds identifiers to that account (proving control of the domains), and requests certificate issuance for those domains while logged in to the account.  

In ACME, the account is represented by a account key pair.  The "add a domain" function is accomplished by authorizing the key pair for a given domain.  Certificate issuance and revocation are authorized by a signature with the key pair.

The first phase of ACME is for the client to establish an authorization with the server for an account key pair to act for the identifier(s) that it wishes to include in the certificate.  To do this, the client must demonstrate to the server both (1) that it holds the private key of the account key pair, and (2) that it has authority over the identifier being claimed.

Proof of possession of the account key is built into the ACME protocol.  All messages from the client to the server are signed by the client, and the server verifies them using the public key of the account key pair.

To verify that the client controls the identifier being claimed, the server issues the client a set of challenges.  Because there are many different ways to validate possession of different types of identifiers, the server will choose from an extensible set of challenges that are appropriate for the identifier being claimed.  The client responds with a set of responses that tell the server which challenges the client has completed.  The server then validate the challenges to check that the client has accomplished the challenge.

For example, if the client requests a domain name, the server might challenge the client to provision a record in the DNS under that name, or to provision a file on a web server reference by an A or AAAA record under that name.  The server would then query the DNS for the record in question, or send an HTTP request for the file.  If the client provisioned the DNS or the web server as expected, then the server considers the client authorized for the domain name.

~~~~~~~~~~

      Client                                                  Server

      (identifier, key)
      Signature                     ------->

                                    <-------              Challenges

      Responses
      Signature                     ------->

                                    <-------           Authorization

~~~~~~~~~~

Once the client has authorized an account key pair for an identifier, it can use the key pair to authorize the issuance of certificates for the identifier.  To do this, the client sends a PKCS#10 Certificate Signing Request (CSR) to the server (indicating the identifier(s) to be included in the issued certificate), a set of links to any required authorizations, and a signature over the CSR by the private key of the authorized key pair.

If the server agrees to issue the certificate, then it creates the certificate and provides it in its response.  The certificate is assigned a URI, which the client can use to renew the certificate as long as the authorizations that underlie it are valid.

~~~~~~~~~~

      Client                                                 Server

      CSR
      Authorization URIs
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


Note that while ACME is defined with enough flexibility to handle different types of identifiers in principle, the primary use case addressed by this document is the case where domain names are used as identifiers.  For example, all of the identifier validation challenges described in Section {{identifier-validation-challenges}} below address validation of domain names.  The use of ACME for other protocols will require further specification, in order to describe how these identifiers are encoded in the protocol, and what types of validation challenges the server might require.


# Certificate Management

In this section, we describe the certificate management functions that ACME enables:

  * Key Authorization
  * Certificate Issuance
  * Certificate Revocation

Each of these functions is accomplished by the client sending a sequence of HTTPS requests to the server, carrying JSON messages.  Each subsection below describes the message formats used by the function, and the order in which messages are sent.

ACME is structured as a REST application with four types of resources:

* Authorization resources, representing an account key's authorization to act for an identifier
* Certificate resources, represnting issued certificates
* A "new-authorization" resource
* A "new-certificate" resource

The remainder of this section provides the details of how these resources are structured and how the ACME protocol makes use of them.

At the beginning of the ACME process, the client must be configured with URLs for the server's new-authorization and new-certificate resources.  The client learns URIs for any authorization and certificate resources it requires through the ACME protocol.

All ACME requests with a non-empty body MUST encapsulate the body in a JWS object.  The server MUST verify the JWS before processing the request.  (For readability, however, the examples below omit this encapsulation.)

## Authorization Resources

An ACME authorization resource represents server's authorization for an account key pair to represent an identifier.  In addition to a public key and identifier, an authorization includes several metadata fields, such as the status of the authorization (e.g., "pending", "valid", or "revoked") and which challenges were used to validate possession of the identifier.

The structure of an ACME authorization resource is as follows:

identifier (required, dictionary of string):
: The identifier that the account key is authorized to represent
  
  type (required, string):
  : The type of identifier.  
  
  value (required, string):
  : The identifier itself.  

key (required, dictionary):
: The public key of the account key pair, encoded as a JSON Web Key object {{I-D.ietf-jose-json-web-key}}.

status (optional, string):
: The status of this authorization.  Possible values are: "pending", "valid", and "invalid".  If this field is missing, then the default value is "pending".

expires (optional, string):
: The date after which the server will consider this authorization invalid, encoded in the format specified in RFC 3339 {{RFC3339}}.

challenges (required, dictionary):
: The challenges that the client needs to fulfill in order to prove possession of the identifier (for pending authorizations).  For final authorizations, the challenges that were used.  Each key in the dictionary is a type of challenge, and the value is a dictionary with parameters required to validate the challenge, as specified in Section {identifier-validation-challenges}.

combinations (optional, array of arrays):
: A collection of sets of challenges, each of which would be sufficient to prove possession of the identifier. Clients SHOULD complete a set of challenges that that covers at least one set in this array. Challenges are represented by their keys in the challenges dictionary (i.e., by type).

contact (optional, array of string PRIVATE):
: An array of URIs that the server can use to contact the client for issues related to this authorization. For example, the server may wish to notify the client about server-initiated revocation, or check with the client on future authorizations (see the "recoveryContact" challenge type).

recoveryToken (optional, string PRIVATE):
: An opaque token that the client can present to demonstrate that it participated in a prior authorization transaction.  This field MUST NOT be present in an authorization object with a status other than "valid".


The only type of identifier defined by this specification is a fully-qualified domain name (type: "dns").  The value of the identifier MUST be the ASCII representation of the domain name.

By default, ACME authorization resources are represented as JSON objects.  Implementations MUST support this representation.

~~~~~~~~~~

{
  "status": "valid",
  "expires": "2015-03-01",

  "identifier": {
    "type": "domain",
    "value": "example.org"
  },

  "key": { /* JWK */ },

  "contact": [
    "mailto:cert-admin@example.com",
    "tel:+12025551212"
  ],

  "challenges": [
    "simpleHttps": {
      "status": "valid",
      "validated": "2014-12-01T12:05Z",
      "token": "IlirfxKKXAsHtmzK29Pj8A"
      "path": "Hf5GrX4Q7EBax9hc2jJnfw"
    },
    "recoveryToken": {
      "status": "valid",
      "validated": "2014-12-01T12:07Z",
      "token": "23029d88d9e123e"
    }
  ],
}

~~~~~~~~~~

### Private Information in Authorizations

Within ACME, authorization resources are only sent between the client and the server, over a secure channel.  However, most of the contents of an authorization do not need to be secret for security reasons, especially after an authorization has been completed.  CAs that are interested in full transparency might consider publishing the set of authorizations they have established.

In that case, certain private information must be expunged from the authorization before publication:

* The "recoveryToken" field, since this value could be used to hijack the client's authorization
* The "contact" field, since this information could be used to target the client for spam, phishing, etc.

These fields are marked PRIVATE in the definitions above.  

In addition, some fields within the "challenges" object might contain private data.  Private fields for specific challenges are noted in the specific challenge definitions below, using the same PRIVATE notation.

## Errors

Errors can be reported in ACME both at the HTTP layer and within ACME payloads.  ACME servers can return responses with an HTTP error response codes (4XX or 5XX).  For example:  If the client submits a request using a method not allowed in this document, then the server MAY return status code 405 (Method Not Allowed).

When the server responds with an error status, it SHOULD provide additional information using problem document {{I-D.ietf-appsawg-http-problem}}.  The "type", "detail", and "instance" fields MUST be populated.  To facilitate automatic response to errors, this document defines the following standard tokens for use in the "type" field (within the "urn:acme:" namespace):

| Code           | Semantic                                           |
|:===============|:===================================================|
| malformed      | The request message was malformed                  |
| unauthorized   | The client lacks sufficient authorization          |
| serverInternal | The server experienced an internal error           |
| badCSR         | The CSR is unacceptable (e.g., due to a short key) |

Authorization and challenge objects can also contain error information to indicate why the server was unable to validate authorization.

TODO: Flesh out errors and syntax for them

## Key Authorization

The key authorization process establishes the authorization of an account key pair to manage certificates for a given identifier.  This process must assure the server of two things: First, that the client controls the private key of the key pair, and second, that the client holds the identifier in question.  This process may be repeated to associate multiple identifiers to a key pair (e.g., to request certificates with multiple identifiers), or to associate multiple key pairs with an identifier (e.g., for load balancing).

As illustrated by the figure in the overview section above, the authorization process proceeds in two phases.  The client first requests a new authorization, and then the server issues challenges that the client responds to.

To begin the key authorization process, the client sends a POST request to the server's new-authorization resource.  The body of the POST request MUST contain a JWS object, whose payload MUST be an initial authorization object.  This JWS object MUST contain the "identifier" field, so that the server knows what identifier is being authorized.  The client MAY provide contact information in the "contact" field in this or any subsequent request.

~~~~~~~~~~

POST /acme/new-authorization HTTP/1.1
Host: example.com

{
  "identifier": {
    "type": "domain",
    "value": "example.org"
  },

  "contact": [
    "mailto:cert-admin@example.com",
    "tel:+12025551212"
  ],
}
/* Signed as JWS */

~~~~~~~~~~

Before processing the authorization further, the server SHOULD determine whether it is willing to issue certificates for the identifier.  For example, the server should check that the identifier is of a supported type.  Servers might also check names against a blacklist of known high-value identifiers.  If the server is unwilling to issue for the identifier, it SHOULD return a 403 (Forbidden) error, with a problem document describing the reason for the rejection.

If the server is willing to proceed, it builds a pending authorization object from the initial authorization object submitted by the client.

* "identifier" the identifier submitted by the client.
* "key": the key used to verify the client's JWS request (i.e., the contents of the "jwk" field in the JWS header)
* "status": SHOULD be "pending" (MAY be omitted)
* "challenges" and "combinations": As selected by the server's policy for this identifier
* "contact": the "contact" field submitted by the client, if provided
* The "expires" and "recoveryToken" fields MUST be absent.

The server allocates a new URI for this authorization, and returns a 201 (Created) response, with the authorization URI in a Location header field, and the JSON authorization object in the body.

~~~~~~~~~~

HTTP/1.1 201 Created
Content-Type: application/json
Location: https://example.com/authz/asdf

{
  "identifier": {
    "type": "domain",
    "value": "example.org"
  },

  "key": { /* JWK from JWS header */ },

  "contact": [
    "mailto:cert-admin@example.com",
    "tel:+12025551212"
  ],

  "challenges": {
    "simpleHttps": {
      "token": "IlirfxKKXAsHtmzK29Pj8A"
    },
    "dns": {
      "token": "DGyRejmCefe7v4NfDGDKfA"
    },
    "recoveryToken": {}
  },

  "combinations": [ 
    ["simpleHttps", "recoveryToken"],
    ["dns", "recoveryToken"]
  ]
}

~~~~~~~~~~

The client needs to respond with information to complete the challenges.  To do this, the client updates the authorization object received from the server by filling in any required information in the elements of the "challenges" dictionary.  For example, if the client wishes to complete the "simpleHttps" challenge, it needs to provide the "path" component.  (This is also the stage where the client should perform any actions required by the challenge.)

The client sends these updates back to the server in the form of a JSON merge patch {{RFC7386}} to the authorization document, carried in a POST request to the authorization URI (not the new-authorization URI).  Using a patch allows the client to send information only for challenges it is responding to.  (It is also harmless to send the whole authorization document.)

~~~~~~~~~~

POST /acme/authz/asdf HTTP/1.1
Host: example.com

{
  "challenges": {
    "simpleHttps": {
      "path": "Hf5GrX4Q7EBax9hc2jJnfw"
    },
    "recoveryToken": {
      "token": "23029d88d9e123e"
    }
  }
}
/* Signed as JWS */

~~~~~~~~~~

The server updates the authorization document by applying the patch.  Before applying the patch, however, the server MUST delete any fields in the patch besides "challenges" and "contact", since these are the only fields that the client may modify.  Similar constraints may need to be applied to individual challenges (e.g., not letting the client modify the "token" field in a "simpleHttps" challenge).

Presumably, the client's responses provide the server with enough information to validate one or more challenges.  The server is said to "finalize" the authorization when it has completed all the validations it is going to complete, and assigns the authorization a status of "valid" or "invalid", corresponding to whether it considers the account key  authorized for the identifier.  If the final state is "valid", the server MUST add an "expires" field to the authorization.  When finalizing an authorization, the server MAY remove the "combinations" field (if present), remove any unfulfilled challenges, or add a "recoveryToken" field.

Usually, the validation process will take some time, in which case the server MUST provide the updated pending authorization object in a 202 (Accepted) response and process the validations asynchronously.  The server MAY provide a Retry-After header in its 202 response to indicate how long it expects the validation to take.  If the server is able to finalize authorization immediately, it MUST return the authorization in a 200 (OK) response.

If the server's response to the client contains a pending authorization, it will need to periodically send a GET request to the authorization URI  until the authorization is returned with a "status" value of "valid" or "invalid", or until the client times out.

~~~~~~~~~~

GET /acme/authz/asdf HTTP/1.1
Host: example.com

HTTP/1.1 200 OK

{
  "status": "valid",
  "expires": "2015-03-01",

  "identifier": {
    "type": "domain",
    "value": "example.org"
  },

  "key": { /* JWK */ },

  "contact": [
    "mailto:cert-admin@example.com",
    "tel:+12025551212"
  ],

  "challenges": [
    "simpleHttps": {
      "status": "valid",
      "validated": "2014-12-01T12:05Z",
      "token": "IlirfxKKXAsHtmzK29Pj8A"
      "path": "Hf5GrX4Q7EBax9hc2jJnfw"
    },
    "recoveryToken": {
      "status": "valid",
      "validated": "2014-12-01T12:07Z",
      "token": "23029d88d9e123e"
    }
  ],
}

~~~~~~~~~~


### Recovery Tokens

A recovery token is a fallback authentication mechanism.  In the event that a client loses all other state, including authorized key pairs and key pairs bound to certificates, the client can use the recovery token to prove that it was previously authorized for the identifier in question.

This mechanism is necessary because once an ACME server has issued an Authorization Key for a given identifier, that identifier enters a higher-security state, at least with respect the ACME server.  That state exists to protect against attacks such as DNS hijacking and router compromise which tend to inherently defeat all forms of Domain Validation.  So once a domain has begun using ACME, new DV-only authorization will not be performed without proof of continuity via possession of an Authorized Private Key or potentially a Subject Private Key for that domain.

This higher state of security poses some risks.  From time to time, the administrators and owners of domains may lose access to keys they have previously had issued or certified, including Authorized private keys and Subject private keys.  For instance, the disks on which this key material is stored may suffer failures, or passphrases for these keys may be forgotten.  In some cases, the security measures that are taken to protect this sensitive data may contribute to its loss.

Recovery Tokens and Recovery Challenges exist to provide a fallback mechanism to restore the state of the domain to the server-side administrative security state it was in prior to the use of ACME, such that fresh Domain Validation is sufficient for reauthorization.

Recovery tokens are therefore only useful to an attacker who can also perform Domain Validation against a target domain, and as a result client administrators may choose to handle them with somewhat fewer security precautions than Authorized and Subject private keys, decreasing the risk of their loss.

Recovery tokens come in several types, including high-entropy passcodes (which need to be safely preserved by the client admin) and email addresses (which are inherently hard to lose, and which can be used for verification, though they may be a little less secure).

Recovery tokens are employed in response to Recovery Challenges.  Such challenges will be available if the server has issued Recovery Tokens for a given domain, and the combination of a Recovery Challenge and a domain validation Challenge is a plausible alternative to other challenge sets for domains that already have extant Authorized keys.

## Certificate Issuance

The holder of an authorized key pair for an identifier may use ACME to request that a certificate be issued for that identifier.  The client makes this request using a "certificateRequest" message, which contains a Certificate Signing Request (CSR) {{RFC2986}} and a signature by the authorized key pair.

type (required, string):
: "certificateRequest"

csr (required, string):
: A CSR encoding the parameters for the certificate being requested.  The CSR is sent in base64-encoded version the DER format.  (Note: This field uses the same modified base64-encoding rules used elsewhere in this document, so it is different from PEM.)

signature (required, object):
: A signature object reflecting a signature by an authorized key pair over the CSR.


~~~~~~~~~~

{
  "type": "certificateRequest",
  "csr": "5jNudRx6Ye4HzKEqT5...FS6aKdZeGsysoCo4H9P",
  "signature": {
    "alg": "RS256",
    "nonce": "h5aYpWVkq-xlJh6cpR-3cw",
    "sig": "KxITJ0rNlfDMAtfDr8eAw...fSSoehDFNZKQKzTZPtQ",
    "jwk": {
      "kty":"RSA",
      "e":"AQAB",
      "n":"KxITJ0rNlfDMAtfDr8eAw...fSSoehDFNZKQKzTZPtQ"
    }
  }
}

~~~~~~~~~~

The CSR encodes the client's requests with regard to the content of the certificate to be issued.  The CSR MUST contain at least one extensionRequest attribute {{RFC2985}} requesting a subjectAltName extension, containing the requested identifiers.

<!-- TODO: Any other constraints on the CSR? -->

The values provided in the CSR are only a request, and are not guaranteed.  The server or CA may alter any fields in the certificate before issuance.  For example, the CA may remove identifiers that are not authorized for the key indicated in the "authorization" field.

If the CA decides to issue a certificate, then the server responds with a certificate message.  (Of course, the server may also respond with an error message if issuance is denied, or a defer message if there may be some delay in issuance.)

type (required, string):
: "certificate"

certificate (required, string):
: The issued certificate, as a base64-encoded DER certificate.

chain (optional, array of string):
: A chain of CA certificates which are parents of the issued certificate.  Each certificate is in base64-encoded DER form (not PEM, as for CSRs above).  This array MUST be presented in the same order as would be required in a TLS handshake {{RFC5246}}.

refresh (optional, string):
: An HTTP or HTTPS URI from which updated versions of this certificate can be fetched.

~~~~~~~~~~

{
  "type": "certificate",
  "certificate": "Zmzdx7UKvwDJ6bk...YBX22NPGQZyYcg",
  "chain": [
    "WUn8L2vLT553pIWJ2...gJ574o2anls1k2p",
    "y3O4puZa9r5KBk1LX...Ya7jlaAZUfuYZGZ"
  ],
  "refresh": "https://example.com/refresh/Dr8eAwTVQfSS/"
}

~~~~~~~~~~

The certificate message allows the server to provide the certificate itself, as well as some associated management information.  The chain of CA certificates can simplify TLS server configuration, by allowing the server to suggest the certificate chain that a TLS server using the issued certificate should present.

The refresh URI allows the client to download updated versions of the issued certificate, in the sense of certificates with different validity intervals, but otherwise the same contents (in particular, the same names and public key).  This can be useful in cases where a CA wishes to issue short-lived certificates, but is still willing to vouch for an identifier-key binding over a longer period of time.  To download an updated certificate, the client simply sends a GET request to the refresh URI.


## Certificate Revocation

To request that a certificate be revoked, the client sends a revocationRequest message that indicates the certificate to be revoked, with a signature by an authorized key:

type (required, string):
: "revocationRequest"

certificate (required, string):
: The certificate to be revoked.

signature (required, object):
: A signature object reflecting a signature by an authorized key pair over the certificate.

<!-- TODO: Add other ways to identify a cert, e.g., fingerprint or serial number? -->

~~~~~~~~~~

{
  "type": "revocationRequest",
  "certificate": "Zmzdx7UKvwDJ6bk...YBX22NPGQZyYcg",
  "signature": {
    "alg": "RS256",
    "nonce": "OQqU4VlhXhvZW9FIqNW-jg",
    "sig": "KxITJ0rNlfDMAtfDr8eAw...fSSoehDFNZKQKzTZPtQ",
    "jwk": {
      "kty":"RSA",
      "e":"AQAB",
      "n":"KxITJ0rNlfDMAtfDr8eAw...fSSoehDFNZKQKzTZPtQ"
    }
  }
}

~~~~~~~~~~

Before revoking a certificate, the server MUST verify that the public key indicated in the signature object is authorized to act for all of the identifier(s) in the certificate.  The server MAY also accept a signature by the private key corresponding to the public key in the certificate.

If the revocation fails, the server returns an error message, e.g., an "unauthorized" error if the signing key was not authorized to revoke this certificate.  If the revocation succeeds, then the server confirms with a "revocation" message, which has no payload.

type (required, string):
: "revocation"

~~~~~~~~~~

{
  "type": "revocation"
}

~~~~~~~~~~


# Identifier Validation Challenges

There are few types of identifier in the world for which there is a standardized mechanism to prove possession of a given identifier.  In all practical cases, CAs rely on a variety of means to test whether an entity applying for a certificate with a given identifier actually controls that identifier.

To accommodate this reality, ACME includes an extensible challenge/response framework for identifier validation.  This section describes an initial set of Challenge types.  Each challenge must describe:

* Content of Challenge payloads (in Challenge messages)
* Content of Response payloads (in authorizationRequest messages)
* How the server uses the Challenge and Response to verify control of an identifier

The only general requirement for Challenge and Response payloads is that they MUST be structured as a JSON object, and they MUST contain a parameter "type" that specifies the type of Challenge or Response encoded in the object.

Different challenges allow the server to obtain proof of different aspects of control over an identifier.  In some challenges, like Simple HTTPS and DVSNI, the client directly proves control of an identifier.  In other challenges, such as Recovery or Proof of Possession, the client proves historical control of the identifier, by reference to a prior authorization transaction or certificate.

The choice of which Challenges to offer to a client under which circumstances is a matter of server policy.  A server may choose different sets of challenges depending on whether it has interacted with a domain before, and how.  For example:

| Domain status                                 | Challenges typically sufficient for (re)Authorization |
|:==============================================|:======================================================|
| No known prior certificates or ACME usage     | Domain Validation (DVSNI or Simple HTTPS)             |
| Existing valid certs, first use of ACME       | DV + Proof of Possession of previous CA-signed key    |
| Ongoing ACME usage                            | PoP of previous Authorized key                        |
| Ongoing ACME usage, lost Authorized key       | DV + (Recovery or PoP of ACME-certified Subject key)  |
| ACME usage, all keys and recovery tokens lost | Recertification by another CA + PoP of that key       |

The identifier validation challenges described in this section all relate to validation of domain names.  If ACME is extended in the future to support other types of identifier, there will need to be new Challenge types, and they will need to specify which types of identifier they apply to.

## Simple HTTPS

With Simple HTTPS validation, the client in an ACME transaction proves its control over a domain name by proving that it can provision resources on an HTTPS server that responds for that domain name.  The ACME server challenges the client to provision a file with a specific string as its contents.

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
: The string to be appended to the standard prefix ".well-known/acme-challenge" in order to form the path at which the nonce resource is provisioned.  The result of concatenating the prefix with this value MUST match the "path" production in the standard URI format {{RFC3986}}

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

The challenge proceeds as follows: The ACME server sends the client a random value R and a nonce used to identify the transaction.  The client responds with another random value S.  The server initiates a TLS connection on port 443 to a host with the domain name being validated.  In the handshake, the ACME server sets the Server Name Indication extension set to "\<nonce\>.acme.invalid".  The TLS server (i.e., the ACME client) should respond with a valid self-signed certificate containing both the domain name being validated and the domain name "\<Z\>.acme.invalid", where Z = SHA-256(R &#124;&#124; S).

The ACME server's Challenge provides its random value R, and a random nonce used to identify the transaction:

type (required, string):
: The string "dvsni"

r (required, string):
: A random 32-byte octet, base64-encoded

nonce (required, string):
: A random 16-byte octet string, hex-encoded (so that it can be used as a DNS label)

~~~~~~~~~~

{
  "type": "dvsni",
  "r": "Tyq0La3slT7tqQ0wlOiXnCY2vyez7Zo5blgPJ1xt5xI",
  "nonce": "a82d5ff8ef740d12881f6d3c2277ab2e"
}

~~~~~~~~~~

The ACME server MAY re-use nonce values, but SHOULD periodically refresh them.  ACME clients MUST NOT rely on nonce values being stable over time.

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
: A random 32-byte secret octet string, base64-encoded

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

## Recovery Contact

A server may issue a recovery contact challenge to verify that the client is the same as the entity that previously requested authorization, using contact information provided by the client in a prior authorizationRequest message.

The server's message to the client may request action in-band or out-of-band to ACME.  The server can provide a token in the message that the client provides in its response.  Or the server could provide some out-of-band response channel in its message, such as a URL to click in an email.

type (required, string):
: The string "recoveryContact"

activationURL (optional, string):
: A URL the client can visit to cause a recovery message to be sent to client's contact address.

successURL (optional, string):
: A URL the client may poll to determine if the user has successfully clicked a link or completed other tasks specified by the recovery message.  This URL will return a 200 success code if the required tasks have been completed.  The client SHOULD NOT poll the URL more than once every three seconds.

contact (optional, string)
: A full or partly obfuscated version of the contact URI that the server will use to contact the client.  Client software may present this to a user in order to suggest what contact point the user should check (e.g., an email address).

~~~~~~~~~~

{
  "type": "recoveryContact",
  "activationURL" : "https://example.ca/sendrecovery/a5bd99383fb0",
  "successURL" : "https://example.ca/confirmrecovery/bb1b9928932",
  "contact" : "c********n@example.com"
}

~~~~~~~~~~

type (required, string):
: The string "recoveryContact"

token (optional, string):
: If the user transferred a token from a contact email or call into the client software, the client sends it here.  If it the client has received a 200 success response while polling the RecoveryContact Challenge's successURL, this field SHOULD be omitted.

~~~~~~~~~~

{
  "type": "recoveryContact",
  "token": "23029d88d9e123e"
}

~~~~~~~~~~

If the value of the "token" field matches the value provided in the out-of-band message to the client, or if the client has completed the required out-of-band action, then the validation succeeds.  Otherwise, the validation fails.


## Recovery Token

A recovery token is a simple way for the server to verify that the client was previously authorized for a domain.  The client simply provides the recovery token that was provided in the authorize message.

type (required, string):
: The string "recoveryToken"

~~~~~~~~~~

{
  "type": "recoveryToken"
}

~~~~~~~~~~

The response to a recovery token challenge is simple; the client sends the requested token that it was provided by the server earlier.

type (required, string):
: The string "recoveryToken"

token (optional, string):
: The recovery token provided by the server.

~~~~~~~~~~

{
  "type": "recoveryToken",
  "token": "23029d88d9e123e"
}

~~~~~~~~~~

If the value of the "token" field matches a recovery token that the server previously provided for this domain, then the validation succeeds.  Otherwise, the validation fails.


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
: A random 16-byte octet string, base64-encoded

hints (required, object):
: A JSON object that contains various clues for the client about what the requested key is, such that the client can find it.  Entries in the hints object may include:

jwk (required, object):
: A JSON Web Key object describing the public key whose corresponding private key should be used to generate the signature {{I-D.ietf-jose-json-web-key}}

certFingerprints (optional, array):
: An array of certificate fingerprints, hex-encoded SHA1 hashes of DER-encoded certificates that are known to contain this key

certs (optional, array):
: An array of certificates, in PEM encoding, that contain acceptable public keys.

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
    "subjectKeyIdentifiers":  ["d0083162dcc4c8a23ecb8aecbd86120e56fd24e5"],
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
* Clients need to protect recovery key
* CA needs to perform a very wide range of issuance policy enforcement and sanity-check steps
* Parser safety (for JSON, JWK, ASN.1, and any other formats that can be parsed by the ACME server)



