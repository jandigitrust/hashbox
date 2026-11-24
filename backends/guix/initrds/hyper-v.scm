;; Initrd that carries Azure's Hyper-V drivers but only loads them on Hyper-V.
(use-modules (gnu packages linux)
             (gnu system file-systems)
             (gnu system linux-initrd)
             (guix gexp)
             (guix modules))

(define %hashbox-hyper-v-modules
  '("hv_vmbus" "hv_storvsc" "hv_netvsc" "hv_utils"))

(define* (hashbox-initrd file-systems
                         #:key
                         (linux linux-libre)
                         (linux-modules '())
                         (mapped-devices '())
                         keyboard-layout
                         volatile-root?
                         (on-error 'debug))
  "Build an Azure initrd containing conditional Hyper-V modules."
  (unless (null? mapped-devices)
    (error "HashBox initrd does not support mapped devices" mapped-devices))
  (when keyboard-layout
    ;; HashBox uses the kernel's built-in US keymap.  Keeping the argument in
    ;; the signature preserves the operating-system initrd contract.
    #t)

  (define modules-to-load
    (append linux-modules
            (file-system-modules file-systems)
            (if volatile-root? '("overlay") '())))
  (define modules-to-include
    (append %hashbox-hyper-v-modules modules-to-load))
  (define module-directory
    ((@@ (gnu system linux-initrd) flat-linux-module-directory)
     linux modules-to-include))
  (define helper-packages
    (file-system-packages file-systems
                          #:volatile-root? volatile-root?))

  (expression->initrd
   (with-imported-modules
       (source-module-closure '((gnu build linux-boot)
                                (gnu build linux-modules)
                                (guix build utils)
                                (gnu system file-systems)
                                (srfi srfi-1)))
     #~(begin
         (use-modules (gnu build linux-boot)
                      (gnu build linux-modules)
                      (gnu system file-systems)
                      (guix build utils)
                      (rnrs io ports)
                      (srfi srfi-1))

         (set-path-environment-variable "PATH" '("bin" "sbin")
                                        '#$helper-packages)

         (define (microsoft-hyper-v?)
           (any (lambda (file)
                  (and (file-exists? file)
                       (call-with-input-file file
                         (lambda (port)
                           (string-contains-ci (get-string-all port)
                                               "microsoft")))))
                '("/sys/class/dmi/id/sys_vendor"
                  "/sys/class/dmi/id/product_name"
                  "/sys/hypervisor/type")))

         (boot-system
          #:mounts (map spec->file-system
                        '#$(map file-system->spec file-systems))
          #:pre-mount
          (lambda ()
            ;; boot-system has mounted /sys and loaded root modules.  Narrow
            ;; the initial TCB policy before loading the Azure drivers and
            ;; before the real root becomes active.  The securityfs mount
            ;; moves with /sys when boot-system switches to that root.
            (mount "none" "/sys/kernel/security" "securityfs")
            (call-with-output-file "/sys/kernel/security/ima/policy"
              (lambda (port)
                (display "measure func=MODULE_CHECK\nmeasure func=POLICY_CHECK\n"
                         port)))
            (if (microsoft-hyper-v?)
                (begin
                  (display "Microsoft Hyper-V detected; loading Azure drivers...\n")
                  (load-linux-modules-from-directory
                   '#$%hashbox-hyper-v-modules #$module-directory))
                (display "Non-Hyper-V platform; Azure drivers remain unloaded.\n"))
            #t)
          #:linux-modules '#$modules-to-load
          #:linux-module-directory #$module-directory
          #:volatile-root? '#$volatile-root?
          #:on-error '#$on-error)))
   #:name "hashbox-initrd"))
