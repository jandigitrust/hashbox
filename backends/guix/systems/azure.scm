;; Azure system composition for the Guix backend.
(use-modules (hashbox providers azure))

(define hashbox-system-directory (dirname (current-filename)))
(primitive-load (string-append hashbox-system-directory "/../initrds/hyper-v.scm"))

(hashbox-azure-operating-system hashbox-initrd)
