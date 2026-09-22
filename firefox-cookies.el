;;; firefox-cookies.el --- Read cookies from Firefox profiles  -*- lexical-binding: t; -*-

;; Copyright (C) 2026 Dzming Li

;; Author: Dzming Li <i@dzming.li>
;; Version: 0.1.0
;; Package-Requires: ((emacs "29.1"))
;; Keywords: comm, convenience
;; URL: https://github.com/DzmingLi/firefox-cookies.el

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;;; Commentary:

;; Read the cookies applicable to an HTTP(S) URL directly from an explicitly
;; selected Firefox profile.  The package applies domain, path, secure,
;; expiration, and Firefox container rules before returning an alist suitable
;; for an HTTP client.
;;
;; The profile is never guessed or scanned.  This keeps account selection an
;; explicit user decision and avoids accidentally mixing browser identities.
;; Website packages may use `firefox-cookies-get' as their cookie function.

;;; Code:

(require 'cl-lib)
(require 'sqlite)
(require 'subr-x)
(require 'url-parse)
(require 'url-util)

(defgroup firefox-cookies nil
  "Read cookies from explicitly selected Firefox profiles."
  :group 'comm
  :prefix "firefox-cookies-")

(defcustom firefox-cookies-profile-directory nil
  "Firefox profile directory containing cookies.sqlite.

This must be set explicitly; profiles are never scanned or guessed."
  :type '(choice (const :tag "Not configured" nil)
                 (directory :must-match t))
  :group 'firefox-cookies)

(defcustom firefox-cookies-origin-attributes ""
  "Exact Firefox `originAttributes' value to select.

The empty string is Firefox's ordinary, non-container context.  A container
can be selected explicitly with a value such as `^userContextId=2'."
  :type 'string
  :group 'firefox-cookies)

(cl-defstruct (firefox-cookies--record
               (:constructor firefox-cookies--make-record))
  "Cookie read from a Firefox database before URL filtering."
  name value domain path expires secure creation)

(defun firefox-cookies--url-parts (url)
  "Parse URL and return (HOST PATH SECURE).

URL must be an absolute HTTP or HTTPS URL with a host."
  (let* ((parsed (url-generic-parse-url url))
         (host (url-host parsed))
         (scheme (downcase (or (url-type parsed) "")))
         (filename (or (url-filename parsed) "/"))
         (path (car (split-string filename "[?#]" t))))
    (unless (and (stringp host)
                 (not (string-empty-p host))
                 (member scheme '("http" "https")))
      (error "firefox-cookies: URL must be absolute HTTP(S): %s" url))
    (list (downcase host)
          (if (and path (string-prefix-p "/" path)) path "/")
          (string-equal scheme "https"))))

(defun firefox-cookies--domain-matches-p (domain host)
  "Return non-nil when cookie DOMAIN applies to HOST."
  (let ((domain (downcase domain))
        (host (downcase host)))
    (if (string-prefix-p "." domain)
        (let ((bare (substring domain 1)))
          (or (string-equal host bare)
              (string-suffix-p (concat "." bare) host)))
      (string-equal domain host))))

(defun firefox-cookies--domain-candidates (host)
  "Return Firefox database domain candidates for HOST."
  (let ((candidates (list host (concat "." host)))
        (start 0))
    (while (string-match "\\." host start)
      (push (substring host (match-beginning 0)) candidates)
      (setq start (match-end 0)))
    (delete-dups candidates)))

(defun firefox-cookies--path-matches-p (cookie-path request-path)
  "Return non-nil when COOKIE-PATH applies to REQUEST-PATH."
  (let ((cookie-path (if (string-empty-p cookie-path) "/" cookie-path)))
    (or (string-equal cookie-path request-path)
        (and (string-prefix-p cookie-path request-path)
             (or (string-suffix-p "/" cookie-path)
                 (and (> (length request-path) (length cookie-path))
                      (eq (aref request-path (length cookie-path)) ?/)))))))

(defun firefox-cookies--records-to-alist (records)
  "Convert RECORDS to an alist in RFC 6265 transmission order."
  (mapcar
   (lambda (record)
     (cons (firefox-cookies--record-name record)
           (firefox-cookies--record-value record)))
   (cl-stable-sort
    (copy-sequence records)
    (lambda (left right)
      (let ((left-length (length (firefox-cookies--record-path left)))
            (right-length (length (firefox-cookies--record-path right))))
        (if (= left-length right-length)
            (< (or (firefox-cookies--record-creation left) 0)
               (or (firefox-cookies--record-creation right) 0))
          (> left-length right-length)))))))

(defun firefox-cookies--records-for-url (records url)
  "Filter RECORDS for URL and return a cookie alist."
  (pcase-let* ((`(,host ,path ,secure) (firefox-cookies--url-parts url))
               (now (float-time))
               (applicable
                (cl-remove-if-not
                 (lambda (record)
                   (and
                    (firefox-cookies--domain-matches-p
                     (firefox-cookies--record-domain record) host)
                    (firefox-cookies--path-matches-p
                     (firefox-cookies--record-path record) path)
                    (or (not (firefox-cookies--record-secure record)) secure)
                    (or (null (firefox-cookies--record-expires record))
                        (> (firefox-cookies--record-expires record) now))))
                 records)))
    (firefox-cookies--records-to-alist applicable)))

(defun firefox-cookies--store-file (profile-directory)
  "Return the cookie store inside PROFILE-DIRECTORY."
  (unless (and (stringp profile-directory)
               (not (string-empty-p (string-trim profile-directory))))
    (error "firefox-cookies: set an explicit profile directory"))
  (let* ((profile (expand-file-name profile-directory))
         (file (expand-file-name "cookies.sqlite" profile)))
    (unless (and (file-directory-p profile) (file-readable-p profile))
      (error "firefox-cookies: profile directory is not readable: %s" profile))
    (unless (and (file-regular-p file) (file-readable-p file))
      (error "firefox-cookies: cookie database is not readable: %s" file))
    file))

(defun firefox-cookies--sqlite-readonly-uri (path)
  "Convert PATH to a safely escaped read-only SQLite URI."
  (concat "file:"
          (url-hexify-string
           (expand-file-name path)
           (cons ?/ url-unreserved-chars))
          "?mode=ro&cache=private"))

(defun firefox-cookies--query-database (path query)
  "Run QUERY against the Firefox database at PATH.

QUERY receives a database handle and schema name.  First attach the Firefox
database read-only.  If SQLite cannot read the live database, retry against a
temporary database/WAL snapshot."
  (let ((run-query
         (lambda (database schema)
           (let (transaction)
             (unwind-protect
                 (progn
                   (sqlite-execute database "BEGIN")
                   (setq transaction t)
                   (prog1 (funcall query database schema)
                     (sqlite-execute database "COMMIT")
                     (setq transaction nil)))
               (when transaction
                 (ignore-errors (sqlite-execute database "ROLLBACK"))))))))
    (condition-case readonly-error
        (let (database)
          (unwind-protect
              (progn
                ;; `sqlite-open' lacks a read-only argument.  Attach the Firefox
                ;; database to an in-memory main database using a read-only URI.
                (setq database (sqlite-open))
                (sqlite-execute
                 database "ATTACH DATABASE ? AS cookies"
                 (list (firefox-cookies--sqlite-readonly-uri path)))
                (funcall run-query database "cookies"))
            (when database
              (ignore-errors (sqlite-close database)))))
      (sqlite-error
       (condition-case snapshot-error
           (let (snapshot-directory database)
             (unwind-protect
                 (let ((snapshot-name (file-name-nondirectory path)))
                   (setq snapshot-directory
                         (make-temp-file "firefox-cookies-snapshot-" t))
                   (dolist (suffix '("" "-wal" "-shm"))
                     (let ((source (concat path suffix)))
                       (when (file-readable-p source)
                         (copy-file
                          source
                          (expand-file-name
                           (concat snapshot-name suffix)
                           snapshot-directory)
                          t))))
                   (setq database
                         (sqlite-open
                          (expand-file-name snapshot-name snapshot-directory)))
                   (funcall run-query database "main"))
               (when database
                 (ignore-errors (sqlite-close database)))
               (when snapshot-directory
                 (ignore-errors (delete-directory snapshot-directory t)))))
         (error
          (error
           "firefox-cookies: database read failed (read-only: %s; snapshot: %s)"
           (error-message-string readonly-error)
           (error-message-string snapshot-error))))))))

(defun firefox-cookies--select-firefox (database schema url origin-attributes)
  "Select cookies for URL from Firefox DATABASE and SCHEMA.

Only cookies with the exact ORIGIN-ATTRIBUTES value are considered."
  (pcase-let* ((`(,host ,_path ,_secure) (firefox-cookies--url-parts url))
               (domains (firefox-cookies--domain-candidates host))
               (placeholders (mapconcat (lambda (_domain) "?") domains ","))
               (table (concat schema ".moz_cookies"))
               (rows
                (sqlite-select
                 database
                 (concat
                  "SELECT name, value, host, path, expiry, isSecure, "
                  "creationTime FROM " table " WHERE host IN ("
                  placeholders ") AND originAttributes = ?")
                 (append domains (list origin-attributes))))
               (records
                (mapcar
                 (lambda (row)
                   (let ((expiry (nth 4 row)))
                     (firefox-cookies--make-record
                      :name (nth 0 row)
                      :value (nth 1 row)
                      :domain (nth 2 row)
                      :path (or (nth 3 row) "/")
                      :expires (and (numberp expiry)
                                    (not (zerop expiry))
                                    (if (> expiry 100000000000)
                                        (/ expiry 1000.0)
                                      expiry))
                      :secure (not (zerop (or (nth 5 row) 0)))
                      :creation (nth 6 row))))
                 rows)))
    (firefox-cookies--records-for-url records url)))

(defun firefox-cookies--read-firefox (path url origin-attributes)
  "Read cookies for URL from Firefox database PATH.

ORIGIN-ATTRIBUTES selects the exact Firefox container context."
  (firefox-cookies--query-database
   path
   (lambda (database schema)
     (firefox-cookies--select-firefox
      database schema url origin-attributes))))

;;;###autoload
(defun firefox-cookies-get (url)
  "Return Firefox cookies applicable to URL as ((NAME . VALUE) ...)."
  (let ((path (firefox-cookies--store-file
               firefox-cookies-profile-directory)))
    (firefox-cookies--read-firefox
     path url firefox-cookies-origin-attributes)))

(provide 'firefox-cookies)
;;; firefox-cookies.el ends here
