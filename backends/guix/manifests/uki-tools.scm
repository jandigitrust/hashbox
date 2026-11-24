;; Source-built EFI stub only: this does not install systemd as guest init.
;; The upstream release archive is a fixed, content-addressed input.
(use-modules (guix packages)
             (guix base16)
             (guix download)
             (guix gexp)
             (guix build-system meson)
             ((guix licenses) #:prefix license:)
             (gnu packages base)
             (gnu packages gperf)
             (gnu packages linux)
             (gnu packages pkg-config)
             (gnu packages python)
             (gnu packages python-xyz))

(define hashbox-uki-tools
  (package
    (name "hashbox-uki-tools")
    (version "261.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/systemd/systemd/archive/refs/tags/v"
                                  version ".tar.gz"))
              (sha256 (base16-string->bytevector "3f8d3d3969af7214bda600930e14c6a24135eb3dce1ba7f1b980b74e6dc15b72"))))
    (build-system meson-build-system)
    (arguments
     (list
      #:tests? #f ; The complete signed UKI has separate replay and boot gates.
      #:configure-flags
      #~(list "-Dauto_features=disabled" "-Dbootloader=enabled" "-Defi=true"
              "-Dtpm=true" "-Dukify=disabled" "-Dman=disabled" "-Dhtml=disabled"
              "-Dtests=false" "-Dtranslations=false" "-Dvcs-tag=false"
              "-Dversion-tag=261.3-hashbox" "-Dtime-epoch=946684800"
              "-Dsbat-distro=hashbox" "-Dsbat-distro-summary=HashBox"
              "-Dsbat-distro-url=https://hashbox.invalid/"
              "-Dsbat-distro-pkgname=hashbox-uki-tools" "-Dsbat-distro-version=261.3")
      #:phases
      #~(modify-phases %standard-phases
          (add-after 'unpack 'fixed-embedded-boot-inputs
            (lambda _
              ;; No companion addons, sidecar initrds/credentials, firmware
              ;; initrd, SMBIOS command-line extension or dynamic console args.
              ;; Keep references type-checked but never execute these calls.
              (substitute* "src/boot/stub.c"
                (("^        (load_all_addons|acquire_previous_initrd|generate_sidecar_initrds|generate_boot_secret_initrd|cmdline_append_and_measure_smbios|cmdline_append_console)\\(" call)
                 (string-append "        if (false) " (string-trim call))))))
          (replace 'build
            (lambda _
              (invoke "ninja" "src/boot/linuxx64.efi.stub")))
          (replace 'install
            (lambda _
              (install-file "src/boot/linuxx64.efi.stub"
                            (string-append #$output "/libexec"))
              (let ((assembler (string-append #$output "/bin/hashbox-ukify")))
                (mkdir-p (dirname assembler))
                (copy-file "../systemd-261.3/src/ukify/ukify.py" assembler)
                (chmod assembler #o555)))))))
    (native-inputs (list pkg-config gperf python python-jinja2 python-pyelftools))
    (inputs (list libcap))
    (home-page "https://systemd.io/")
    (synopsis "Pinned EFI stub and UKI assembler for HashBox")
    (description "Builds only the AMD64 EFI stub and installs the upstream UKI
assembler.  External boot-input extension paths are disabled; the guest retains
Guix and Shepherd.  This is experimental boot-chain tooling, not attestation.")
    (license license:lgpl2.1+)))

hashbox-uki-tools
