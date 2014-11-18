# Automated Certificate Management Environment (ACME)

ACME is a protocol for automating the management of domain-validation certificates, based on a simple JSON-over-HTTPS interface.  This repository contains the specification for ACME.

We're using the IETF toolchain and formats for this specification.  The "source" version of the specification is the markdown version, `draft-barnes-acme.md`.  Other versions are generated from that, and the versions in the repo may be out of date.

This spec is a work in progress.  Eventually, we hope to move it to the IETF process to become an RFC, but for now -- pull requests welcome!

## Quickstart

Just open `draft-barnes-acme.md` in a text editor.

If you want to reproduce the other files:

```
> sudo port install xml2rfc
> gem install kramdown-rfc2629
> kramdown-rfc2629 draft-barnes-acme.md >draft-barnes-acme.xml
> xml2rfc draft-barnes-acme.xml
> xml2html draft-barnes-acme.xml
```

You can also use a prototype [web version](http://ipv.sx/draftr/) of these tools.
