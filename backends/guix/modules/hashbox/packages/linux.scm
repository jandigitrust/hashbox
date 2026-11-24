;;; Provider-neutral confidential-computing guest kernel capabilities.
(define-module (hashbox packages linux)
  #:use-module (gnu packages linux)
  #:export (hashbox-linux-coco))

(define hashbox-linux-coco
  ;; Inherit the source, toolchain and base configuration from channels.scm.
  ;; customize-linux runs verify-config after Kconfig resolution: a silently
  ;; dropped requested option fails the build. Host SEV/KVM support is not a
  ;; substitute for this guest memory-encryption option.
  (customize-linux
   #:linux linux-libre
   #:name "linux-libre-hashbox-coco"
   #:extra-version "hashbox-coco"
   #:configs '("CONFIG_AMD_MEM_ENCRYPT=y"
               "CONFIG_SEV_GUEST=m")))
