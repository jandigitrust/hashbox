;; The full Guix package graph is anchored to the Guix 1.5.0 release.
;; Updating this commit is an explicit, reviewable change.
(list
 (channel
  (name 'guix)
  (url "https://codeberg.org/guix/guix.git")
  (branch "master")
  (commit "230aa373f315f247852ee07dff34146e9b480aec")
  (introduction
   (make-channel-introduction
    "9edb3f66fd807b096b48283debdcddccfea34bad"
    (openpgp-fingerprint
     "BBB0 2DDF 2EB2 5C1B AD84 A664 74EF 4F03 59B6 5FBD")))))
