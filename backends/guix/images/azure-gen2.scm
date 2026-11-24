;; Azure Generation 2 disk layout for HashBox.
(use-modules (gnu image)
             (gnu system image))

(define image-directory (dirname (current-filename)))
(define hashbox-operating-system
  (primitive-load (string-append image-directory "/../systems/azure.scm")))

(image
 (inherit efi-disk-image)
 (name 'HashBox-azure-gen2.raw)
 (partition-table-type 'gpt)
 (size (* 4 (expt 2 30)))
 (volatile-root? #f)
 (operating-system hashbox-operating-system))
