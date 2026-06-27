# ed25519-clj

**Recover an Ed25519 public key (and its `did:key`) from a raw 32-byte seed — in
pure Clojure, no BouncyCastle, no native code, babashka-friendly.**

The JVM's JCA `Ed25519` provider can *sign* with a PKCS8 seed and *verify* with an
X.509 SPKI public key, but it offers **no way to derive the public key from a raw
seed**. On babashka / GraalVM it's worse: the `EdEC*` interface classes aren't on
the image and BouncyCastle isn't on the path. So if you're holding a raw seed — a
stored signing key, a wallet or tenant secret, a `did:key` you need to reconstruct —
you're stuck generating a throwaway keypair or pulling in a heavy dependency.

This library does the derivation directly, per **RFC 8032 §5.1.5 (edwards25519)**:

```
A = clamp(SHA-512(seed)[0..32]) · B
pubkey = compress(A)
```

using **only `java.security.MessageDigest` (SHA-512) + `BigInteger`** — it runs
anywhere Clojure and SHA-512 do, **babashka included**.

## Install

deps.edn (git dep):

```clojure
io.github.com-junkawasaki/ed25519-clj {:git/sha "<sha>"}
```

## Use

```clojure
(require '[ed25519.core :as ed])

(ed/pubkey-from-seed seed-bytes)        ;=> ^bytes (32)   raw public key
(ed/seed-hex->pubkey-hex "9d61b1…")     ;=> "4bafa390…"   hex → hex
(ed/did-key-from-seed seed-bytes)       ;=> "did:key:z6Mk…"
(ed/did-key-from-seed-hex "9d61b1…")    ;=> "did:key:z6Mk…"

;; sign / verify / parse
(ed/sign seed-bytes msg-bytes)          ;=> ^bytes (64)  Ed25519 signature
(ed/verify pub-bytes msg-bytes sig)     ;=> true
(ed/verify-did "did:key:z6Mk…" msg sig) ;=> true   (signer identified by did:key)
(ed/did-key->pubkey "did:key:z6Mk…")    ;=> ^bytes (32)  the inverse of did-key-from-pub

;; vector-free correctness check: sign with PKCS8(seed), verify under the derived pubkey
(ed/verify-derivation seed-bytes)       ;=> true
```

Also exposed: `did-key-from-pub`, `private-from-seed` / `public-from-raw` (JCA
key objects from raw bytes), `hexify` / `unhex`, `b58`, and the field constant `P`.

## Correctness

`bb test` (or `clojure -X:test`) runs two independent oracles, neither relying on a
memorized RFC table:

1. **JCA oracle** — generate keypairs with the JVM's own conformant RFC-8032
   provider, pull out the seed (PKCS8 tail) and pubkey (SPKI tail), and assert the
   derivation reproduces the provider's pubkey byte-for-byte across many keys.
2. **Fixed regression vector** — one JCA-verified `(seed → pubkey)` pair, so a
   refactor that breaks determinism fails loudly.

```
$ bb test
Ran 6 tests containing 31 assertions.
0 failures, 0 errors.
```

## Why "no BouncyCastle"

Adding BouncyCastle (or `tink`, or a JNI binding) works on the JVM but defeats the
point on babashka/GraalVM native images and bloats the dependency graph for what is,
mathematically, one scalar multiplication. This is ~120 lines of stdlib Clojure.

## License

Apache-2.0.
