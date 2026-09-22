EMACS ?= emacs

.PHONY: test compile check

test:
	$(EMACS) --batch -Q -L . -L test \
	  -l test/firefox-cookies-test.el \
	  -f ert-run-tests-batch-and-exit

compile:
	$(EMACS) --batch -Q -L . \
	  --eval '(setq byte-compile-error-on-warn t)' \
	  -f batch-byte-compile firefox-cookies.el

check: test compile
