;; Tool closure for deriving the non-promotable Secure Boot capability image.
;; Package resolution is pinned by backends/guix/channels.scm and must run
;; through the authenticated Guix launcher. The private signing key is an external runtime input and
;; is deliberately not represented in this manifest.
(use-modules (guix profiles))
(load (string-append (dirname (current-filename)) "/uki-tools.scm"))

(concatenate-manifests
 (list (packages->manifest (list hashbox-uki-tools))
 (specifications->manifest
 '("bash-minimal"
   "coreutils"
   "diffutils"
   "e2fsprogs"
   "libfaketime"
   "mtools"
   "openssl"
   "python-wrapper"
   "python-pefile"
   "sbsigntools"))))
