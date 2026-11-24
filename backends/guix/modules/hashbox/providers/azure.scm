;;; Thin Azure adapter: Hyper-V boot drivers and Azure cloud-init datasource.
(define-module (hashbox providers azure)
  #:use-module (hashbox system base)
  #:use-module (hashbox packages linux)
  #:export (hashbox-azure-operating-system))

(define (hashbox-azure-operating-system initrd)
  (hashbox-base-operating-system
   #:initrd initrd
   #:kernel hashbox-linux-coco
   ;; NoCloud and ConfigDrive keep the exact Azure artifact locally testable.
   ;; Azure instance credentials arrive from the Azure datasource at first boot.
   #:cloud-init-datasources '("NoCloud" "ConfigDrive" "Azure" "None")))
