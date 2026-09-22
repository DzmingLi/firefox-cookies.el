;;; firefox-cookies-test.el --- Tests for firefox-cookies  -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later

(require 'ert)
(require 'firefox-cookies)

(defmacro firefox-cookies-test--with-profile (&rest body)
  "Create a temporary Firefox profile and evaluate BODY."
  (declare (indent 0) (debug t))
  `(let* ((profile-directory (make-temp-file "firefox-cookies-test-" t))
          (firefox-cookies-profile-directory profile-directory)
          (database-path (expand-file-name "cookies.sqlite" profile-directory))
          (database (sqlite-open database-path)))
     (unwind-protect
         (progn
           (sqlite-execute
            database
            (concat
             "CREATE TABLE moz_cookies ("
             "name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, "
             "isSecure INTEGER, creationTime INTEGER, originAttributes TEXT)"))
           ,@body)
       (when database (sqlite-close database))
       (delete-directory profile-directory t))))

(defun firefox-cookies-test--insert
    (database name value domain path expiry secure creation &optional container)
  "Insert one Firefox cookie into DATABASE."
  (sqlite-execute
   database
   (concat
    "INSERT INTO moz_cookies "
    "(name, value, host, path, expiry, isSecure, creationTime, "
    "originAttributes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
   (list name value domain path expiry secure creation (or container ""))))

(ert-deftest firefox-cookies-filters-and-orders-firefox-cookies ()
  (firefox-cookies-test--with-profile
    (let ((future (+ (floor (float-time)) 3600))
          (past (- (floor (float-time)) 3600)))
      (firefox-cookies-test--insert
       database "root" "one" ".example.com" "/" future 0 1)
      (firefox-cookies-test--insert
       database "account" "two" ".example.com" "/account" future 1 2)
      (firefox-cookies-test--insert
       database "host-only" "three" "www.example.com" "/" future 0 3)
      (firefox-cookies-test--insert
       database "expired" "no" ".example.com" "/" past 0 4)
      (firefox-cookies-test--insert
       database "wrong-path" "no" ".example.com" "/other" future 0 5)
      (firefox-cookies-test--insert
       database "container" "no" ".example.com" "/" future 0 6
       "^userContextId=2")
      (should
       (equal
        (firefox-cookies-get "https://www.example.com/account/settings")
        '(("account" . "two")
          ("root" . "one")
          ("host-only" . "three")))))))

(ert-deftest firefox-cookies-does-not-send-secure-cookie-over-http ()
  (firefox-cookies-test--with-profile
    (firefox-cookies-test--insert
     database "secure" "secret" ".example.com" "/" 0 1 1)
    (should-not
     (firefox-cookies-get "http://example.com/"))))

(ert-deftest firefox-cookies-selects-explicit-firefox-container ()
  (firefox-cookies-test--with-profile
    (firefox-cookies-test--insert
     database "session" "ordinary" ".example.com" "/" 0 0 1)
    (firefox-cookies-test--insert
     database "session" "container" ".example.com" "/" 0 0 2
     "^userContextId=2")
    (let ((firefox-cookies-origin-attributes "^userContextId=2"))
      (should
       (equal
        (firefox-cookies-get "https://example.com/")
        '(("session" . "container")))))))

(ert-deftest firefox-cookies-get-returns-cookie-alist ()
  (firefox-cookies-test--with-profile
    (firefox-cookies-test--insert
     database "first" "1" ".example.com" "/" 0 0 1)
    (firefox-cookies-test--insert
     database "second" "2" ".example.com" "/" 0 0 2)
    (should-error
     (firefox-cookies-get "ftp://example.com/")
     :type 'error)
    (should
     (equal
      (firefox-cookies-get "https://example.com/")
      '(("first" . "1") ("second" . "2"))))))

(provide 'firefox-cookies-test)
;;; firefox-cookies-test.el ends here
