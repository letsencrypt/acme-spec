# NOTE: This Repository is Deprecated

This repository is not active and may not accurately reflect what Let's Encrypt currently implements. It's retained only for history.

All new work happens here: https://github.com/ietf-wg-acme/acme/

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
