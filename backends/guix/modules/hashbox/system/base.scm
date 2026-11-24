;;; Cloud-neutral HashBox operating-system declaration.
(define-module (hashbox system base)
  #:use-module (gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages linux)
  #:use-module (gnu services base)
  #:use-module (gnu services)
  #:use-module (gnu services networking)
  #:use-module (gnu services ssh)
  #:use-module (gnu system accounts)
  #:use-module (guix gexp)
  #:use-module (hashbox provisioning cloud-init)
  #:export (hashbox-base-operating-system))

(define* (hashbox-base-operating-system
          #:key
          initrd
          (kernel linux-libre)
          (cloud-init-datasources
           '("NoCloud" "ConfigDrive" "Ec2" "Azure"
             "GCE" "OpenStack" "None")))
  (operating-system
    (kernel kernel)
    (host-name "hashbox")
    (timezone "Etc/UTC")
    (locale "en_US.utf8")
    (keyboard-layout (keyboard-layout "us"))

    (kernel-arguments
     (list "console=tty0"
           "console=ttyS0,115200n8"
           "earlyprintk=ttyS0,115200"
           ;; Measure initrd activity before its narrower policy is installed.
           "ima_policy=tcb"
           "ima_hash=sha256"
           "ima_template=ima-ng"
           "rootdelay=10"))
    (initrd initrd)

    (bootloader
     (bootloader-configuration
      (bootloader grub-efi-bootloader)
      (targets '("/boot/efi"))
      (terminal-outputs '(console serial))
      (terminal-inputs '(console serial))
      (serial-speed 115200)))
    (file-systems
     (cons (file-system
             (mount-point "/")
             (device (file-system-label "root"))
             (type "ext4"))
           %base-file-systems))

    ;; The account exists in the immutable declaration, but remains locked
    ;; until cloud-init installs a public key supplied for this VM instance.
    (users
     (cons (user-account
            (name "hashbox")
            (comment "HashBox operator")
            (password "!")
            (group "users")
            (supplementary-groups '("wheel")))
           %base-user-accounts))

    (packages
     (append (specifications->packages
              '("bash" "coreutils" "findutils" "grep" "less" "nano" "sed" "python" "nss-certs" "crun" "umoci"))
             %base-packages))

    (services
     (cons* (simple-service
             'hashbox-attestor-files etc-service-type
             `(("hashbox/attestor.oci.tar"
                ,(local-file (string-append (getcwd) "/dist/attestor.oci.tar")))
               ("hashbox/attestor.oci.json"
                ,(local-file (string-append (getcwd) "/dist/attestor.oci.json")))
               ("hashbox/attestor-source-lock.json"
                ,(local-file (string-append (getcwd) "/ATTESTOR_LOCK.json")))
               ("hashbox/prepare-attestor.py"
                ,(local-file (string-append (getcwd) "/toolchain/attestor/prepare-guest-bundle.py")))
               ("hashbox/launch-attestor.sh"
                ,(local-file (string-append (getcwd) "/toolchain/oci/launch-guest-container.sh")))))
            (simple-service
             'hashbox-ima-reader activation-service-type
             #~(begin
                 ;; The kernel publishes IMA measurements as root:root 0440.
                 ;; The unprivileged Attestor needs read access to that log.
                 (chmod "/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha1"
                        #o444)))
            (service dhcpcd-service-type)
            (udev-rules-service
             'hashbox-attestation
             (udev-rule "60-hashbox-attestation.rules"
                        "KERNEL==\"tpm[0-9]*\", OWNER=\"hashbox\", MODE=\"0600\"\nKERNEL==\"tpmrm[0-9]*\", OWNER=\"hashbox\", MODE=\"0600\"\nKERNEL==\"sev-guest\", OWNER=\"hashbox\", MODE=\"0600\"\n"))
            (service openssh-service-type
                     (openssh-configuration
                      (permit-root-login #f)
                      (allow-empty-passwords? #f)
                      (password-authentication? #f)
                      (public-key-authentication? #t)
                      (challenge-response-authentication? #f)
                      (allow-agent-forwarding? #f)))
            (service hashbox-cloud-init-service-type
                     (hashbox-cloud-init-configuration
                      (datasources cloud-init-datasources)
                      (default-user "hashbox")))
            (service agetty-service-type
                     (agetty-configuration
                      (tty "ttyS0")
                      (term "vt100")
                      (baud-rate "115200")
                      (extra-options '("-L"))))
            %base-services))))
