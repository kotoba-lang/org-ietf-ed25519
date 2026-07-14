;; nbb (ClojureScript-on-Node) smoke for the :cljs branch — run with:
;;   nbb --classpath src test/nbb_smoke.cljs
;; Exits nonzero on any failure. The signature is compared against the JVM
;; implementation's output for the same fixture (Ed25519 is deterministic,
;; RFC 8032, so both platforms MUST produce byte-identical signatures --
;; the strongest cross-platform equivalence check available without
;; spawning a JVM from this script).
(require '[ed25519.core :as ed])

(def seed (js/Uint8Array. (into-array (range 32))))
(def msg (.encode (js/TextEncoder.) "cross-platform ed25519"))
;; produced by the :clj branch for the same seed/msg (see core_test.clj's
;; fixture discipline): (ed/hexify (ed/sign (byte-array (range 32)) msg))
(def jvm-sig-hex "24d0acd801f287f929f872e961e657e674e58b459af57b3be038f84acd866cd3287c893c4fa8be5ef16b66fcffbd587389be73960e2a4af6a7fa7aea10839307")

(def checks
  {:did (= "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
           (ed/did-key-from-seed seed))
   :self-check (true? (ed/verify-derivation seed))
   :sig-byte-identical-to-jvm (= jvm-sig-hex (ed/hexify (ed/sign seed msg)))
   :verifies-jvm-sig (true? (ed/verify-did (ed/did-key-from-seed seed) msg
                                           (ed/unhex jvm-sig-hex)))
   :rejects-tampered (false? (ed/verify-did (ed/did-key-from-seed seed)
                                            (.encode (js/TextEncoder.) "tampered")
                                            (ed/unhex jvm-sig-hex)))
   :b58-roundtrip (= "000007ff2a"
                     (ed/hexify (ed/b58-decode (ed/b58 (js/Uint8Array. #js [0 0 7 255 42])))))
   :did-parse-roundtrip (= (ed/hexify (ed/pubkey-from-seed seed))
                           (ed/hexify (ed/did-key->pubkey (ed/did-key-from-seed seed))))})

(println (pr-str checks))
(when-not (every? true? (vals checks))
  (js/process.exit 1))
