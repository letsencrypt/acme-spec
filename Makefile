# Original makefile from https://github.com/martinthomson/i-d-template

# The following tools are used by this file.
# All are assumed to be on the path, but you can override these
# in the environment, or command line.

# Mandatory:
#   https://pypi.python.org/pypi/xml2rfc
xml2rfc ?= xml2rfc

# If you are using markdown files:
#   https://github.com/cabo/kramdown-rfc2629
kramdown-rfc2629 ?= kramdown-rfc2629

# If you are using outline files:
#   https://github.com/Juniper/libslax/tree/master/doc/oxtradoc
oxtradoc ?= oxtradoc.in

# For sanity checkout your draft:
#   https://tools.ietf.org/tools/idnits/
idnits ?= idnits

# For diff:
#   https://tools.ietf.org/tools/rfcdiff/
rfcdiff ?= rfcdiff --browse

# For generating PDF:
#   https://www.gnu.org/software/enscript/
enscript ?= enscript
#   http://www.ghostscript.com/
ps2pdf ?= ps2pdf 

# Where to get references
XML_RESOURCE_ORG_PREFIX ?= http://unicorn-wg.github.io/idrefs


## Work out what to build

draft := $(basename $(lastword $(sort $(wildcard draft-*.xml)) $(sort $(wildcard draft-*.org)) $(sort $(wildcard draft-*.md))))

ifeq (,$(draft))
$(warning No file named draft-*.md or draft-*.xml or draft-*.org)
$(error Read README.md for setup instructions)
endif

draft_type := $(suffix $(firstword $(wildcard $(draft).md $(draft).org $(draft).xml)))

current_ver := $(shell git tag | grep '$(draft)-[0-9][0-9]' | tail -1 | sed -e"s/.*-//")
ifeq (,$(current_ver))
next_ver ?= 00
else
next_ver ?= $(shell printf "%.2d" $$((1$(current_ver)-99)))
endif
next := $(draft)-$(next_ver)
diff_ver := $(draft)-$(current_ver)


## Targets

.PHONY: latest txt html pdf submit diff clean update ghpages

latest: txt html
txt: $(draft).txt
html: $(draft).html
pdf: $(draft).pdf

submit: $(next).txt

idnits: $(next).txt
	$(idnits) $<

## If you'd like the main github page to show the draft text.
readme: $(next).txt
	@echo '```' > README.md
	@cat $(next).txt >> README.md
	@echo '```' >> README.md

clean:
	-rm -f $(draft).{txt,html,pdf} index.html
	-rm -f $(draft)-[0-9][0-9].{xml,md,org,txt,html,pdf}
	-rm -f *.diff.html
ifneq (.xml,$(draft_type))
	-rm -f $(draft).xml
endif

## diff

$(next).xml: $(draft).xml
	sed -e"s/$(basename $<)-latest/$(basename $@)/" $< > $@

ifneq (,$(current_ver))
.INTERMEDIATE: $(addprefix $(draft)-$(current_ver),.txt $(draft_type))
diff: $(draft).txt $(draft)-$(current_ver).txt
	-$(rfcdiff) $^

$(draft)-$(current_ver)$(draft_type):
	git show $(draft)-$(current_ver):$(draft)$(draft_type) > $@
endif

## Recipes

.INTERMEDIATE: $(draft).xml
%.xml: %.md
	XML_RESOURCE_ORG_PREFIX=$(XML_RESOURCE_ORG_PREFIX) \
	  $(kramdown-rfc2629) $< > $@

%.xml: %.org
	$(oxtradoc) -m outline-to-xml -n "$@" $< > $@

%.txt: %.xml
	$(xml2rfc) $< -o $@ --text

%.htmltmp: %.xml
	$(xml2rfc) $< -o $@ --html
%.html: %.htmltmp lib/addstyle.sed lib/style.css
	sed -f lib/addstyle.sed $< > $@

%.pdf: %.txt
	$(enscript) --margins 76::76: -B -q -p - $^ | $(ps2pdf) - $@

## Update this Makefile

# The prerequisites here are what is updated
.INTERMEDIATE: .i-d-template.diff
update: Makefile lib .gitignore SUBMITTING.md
	git diff --quiet -- $^ || \
	  (echo "You have uncommitted changes to:" $^ 1>&2; exit 1)
	-if [ -f .i-d-template ]; then \
	  git diff --exit-code $$(cat .i-d-template) -- $^ > .i-d-template.diff && \
	  rm -f .i-d-template.diff; \
	fi
	git remote | grep i-d-template > /dev/null || \
	  git remote add i-d-template https://github.com/martinthomson/i-d-template.git
	git fetch i-d-template
	[ -f .i-d-template ] && [ $$(git rev-parse i-d-template/master) = $$(cat .i-d-template) ] || \
	  git checkout i-d-template/master $^
	git diff --quiet -- $^ && rm -f .i-d-template.diff || \
	  git commit -m "Update of $^ from i-d-template/$$(git rev-parse i-d-template/master)" $^
	if [ -f .i-d-template.diff ]; then \
	  git apply .i-d-template.diff && \
	  git commit -m "Restoring local changes to $$(git diff --name-only $^ | paste -s -d ' ' -)" $^; \
	fi
	git rev-parse i-d-template/master > .i-d-template

## Update the gh-pages branch with useful files

GHPAGES_TMP := /tmp/ghpages$(shell echo $$$$)
.INTERMEDIATE: $(GHPAGES_TMP)
ifeq (,$(TRAVIS_COMMIT))
GIT_ORIG := $(shell git branch | grep '*' | cut -c 3-)
ifneq (,$(findstring detached from,$(GIT_ORIG)))
GIT_ORIG := $(shell git show -s --format='format:%H')
endif
else
GIT_ORIG := $(TRAVIS_COMMIT)
endif

# Only run upload if we are local or on the master branch
IS_LOCAL := $(if $(TRAVIS),,true)
ifeq (master,$(TRAVIS_BRANCH))
IS_MASTER := $(findstring false,$(TRAVIS_PULL_REQUEST))
else
IS_MASTER :=
endif

index.html: $(draft).html
	cp $< $@

ghpages: index.html $(draft).txt
ifneq (true,$(TRAVIS))
	@git show-ref refs/heads/gh-pages > /dev/null 2>&1 || \
	  ! echo 'Error: No gh-pages branch, run `make setup-ghpages` to initialize it.'
endif
ifneq (,$(or $(IS_LOCAL),$(IS_MASTER)))
	mkdir $(GHPAGES_TMP)
	cp -f $^ $(GHPAGES_TMP)
	git clean -qfdX
ifeq (true,$(TRAVIS))
	git config user.email "ci-bot@example.com"
	git config user.name "Travis CI Bot"
	git checkout -q --orphan gh-pages
	git rm -qr --cached .
	git clean -qfd
	git pull -qf origin gh-pages --depth=5
else
	git checkout gh-pages
	git pull
endif
	mv -f $(GHPAGES_TMP)/* $(CURDIR)
	git add $^
	if test `git status -s | wc -l` -gt 0; then git commit -m "Script updating gh-pages."; fi
ifneq (,$(GH_TOKEN))
	@echo git push https://github.com/$(TRAVIS_REPO_SLUG).git gh-pages
	@git push https://$(GH_TOKEN)@github.com/$(TRAVIS_REPO_SLUG).git gh-pages
endif
	-git checkout -qf "$(GIT_ORIG)"
	-rm -rf $(GHPAGES_TMP)
endif

.PHONY: setup-ghpages
setup-ghpages:
# Check if the gh-pages branch already exists locally
	@if git show-ref refs/heads/gh-pages >/dev/null 2>&1; then \
	  ! echo "Error: gh-pages branch already exists"; \
	else true; fi
# Check if the gh-pages branch already exists on origin
	@if git show-ref origin/gh-pages >/dev/null 2>&1; then \
	  echo 'Warning: gh-pages already present on the origin'; \
	  git branch gh-pages origin/gh-pages; false; \
	else true; fi
	@echo "Initializing gh-pages branch"
	git checkout --orphan gh-pages
	git rm -rf .
	touch index.html
	git add index.html
	git commit -m "Automatic setup of gh-pages."
	git push --set-upstream origin gh-pages
	git checkout -qf "$(GIT_ORIG)"
