# Automated Certificate Management Environment (ACME)

[![Build Status](https://travis-ci.org/letsencrypt/acme-spec.svg)]
(https://travis-ci.org/letsencrypt/acme-spec)

[As HTML](https://letsencrypt.github.io/acme-spec/)

Note: This repository is only for issues and pull requests specific to Let's Encrypt and is not guaranteed to reflect the current state the of the ACME protocol. For a more up-to-date version of this document, please use the [IETF ACME WG repository](https://github.com/ietf-wg-acme/acme).

ACME is a protocol for automating the management of domain-validation certificates, based on a simple JSON-over-HTTPS interface.  This repository contains the specification for ACME.

We're using the IETF toolchain and formats for this specification.  The "source" version of the specification is the markdown version, `draft-barnes-acme.md`.  Other versions are generated from that, and the versions in the repo may be out of date.

This spec is a work in progress.  Eventually, we hope to move it to the IETF process to become an RFC, but for now -- pull requests welcome!

## Quickstart

Just open `draft-barnes-acme.md` in a text editor.

If you want to reproduce the other files, type `make`.

You need to install some tools (see the Makefile for more information).
```sh
# install dependencies for lxml built for xml2rfc
sudo apt-get install libxml2-dev libxslt1-dev
# instead of "sudo pip" that pollutes system-wide packages, use
# virtual Python environment
virtualenv --no-site-packages venv
# remember also to activate the virtualenv before any 'make' run
source venv/bin/activate
pip install xml2rfc
gem install kramdown-rfc2629
```

You can also use a prototype [web version](http://ipv.sx/draftr/) of these tools.
