# Submitting Drafts

Occasionally, you will want to submit versions of your draft to the official
IETF repository.  The following process makes this easy.

Make a submission version of your draft.  The makefile uses git tags to work out
what version to create.  It looks for the last version number you have tagged
the draft with and calculates the next version.  When there are no tags, it
generates a `-00` version.

```sh
$ make submit
```

[Submit the .txt and .xml files](https://datatracker.ietf.org/submit/)
that this produces.

Then you can tag your repository and upload the tags.  The tag you should
use is your draft name with the usual number in place of `-latest`.

```sh
$ git tag draft-ietf-unicorn-protocol-03
$ git push --tags
```
