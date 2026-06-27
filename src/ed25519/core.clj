;; ed25519.core — pure-Clojure Ed25519 PUBLIC-KEY derivation from a raw seed.
;;
;; The JVM's JCA "Ed25519" provider can SIGN with a PKCS8 seed and VERIFY with an
;; X.509 SPKI pubkey, but it gives you NO way to recover the PUBLIC key (hence the
;; did:key) FROM an existing raw 32-byte seed — and on babashka/GraalVM the EdEC
;; interface classes are absent and BouncyCastle is not on the path. So if you hold
;; a raw seed (a stored signing key, a wallet/tenant secret) you cannot get its
;; public key without either generating a fresh keypair or pulling in a native dep.
;;
;; This implements the derivation directly per RFC 8032 §5.1.5 (edwards25519):
;;   A = clamp(SHA-512(seed)[0..32]) · B ;  pubkey = compress(A)
;; using ONLY java.security.MessageDigest (SHA-512) + BigInteger. No BouncyCastle,
;; no JCA EdEC, no native code — it runs anywhere clojure + SHA-512 do, babashka
;; included. Correctness is cross-checked at runtime against the JCA signer
;; (a signature made by the PKCS8(seed) private key verifies under the derived
;; SPKI pubkey), and pinned by a fixed regression vector in the tests.
;;
;;   (require '[ed25519.core :as ed])
;;   (ed/pubkey-from-seed seed-bytes)   ; ^bytes 32   (seed = raw 32 bytes)
;;   (ed/seed-hex->pubkey-hex "9d61…")  ; hex → hex
;;   (ed/did-key-from-seed seed-bytes)  ; "did:key:z6Mk…"
;;   (ed/verify-derivation seed-bytes)  ; true   (JCA self-check, no vector needed)
(ns ed25519.core
  (:require [clojure.string :as str])
  (:import (java.security MessageDigest KeyFactory Signature)
           (java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec)))

;; ── field GF(2^255-19) ────────────────────────────────────────────────────────
(def ^BigInteger P (.subtract (.pow (biginteger 2) 255) (biginteger 19)))
(def ^:private ^BigInteger ONE BigInteger/ONE)
(def ^:private ^BigInteger ZERO BigInteger/ZERO)
(def ^:private ^BigInteger TWO (biginteger 2))

(defn- fadd ^BigInteger [^BigInteger a ^BigInteger b] (.mod (.add a b) P))
(defn- fsub ^BigInteger [^BigInteger a ^BigInteger b] (.mod (.subtract a b) P))
(defn- fmul ^BigInteger [^BigInteger a ^BigInteger b] (.mod (.multiply a b) P))
(defn- finv ^BigInteger [^BigInteger a] (.modPow a (.subtract P TWO) P)) ; Fermat inverse

;; d = -121665 / 121666  (edwards25519 curve constant)
(def ^BigInteger D (fmul (.mod (biginteger -121665) P) (finv (biginteger 121666))))
(def ^:private ^BigInteger TWO-D (fmul TWO D))

;; Base point B (affine, RFC 8032 §5.1) in EXTENDED coords (X:Y:Z:T), T = X·Y/Z.
(def ^:private ^BigInteger BX (biginteger "15112221349535400772501151409588531511454012693041857206046113283949847762202"))
(def ^:private ^BigInteger BY (biginteger "46316835694926478169428394003475163141307993866256225615783033603165251855960"))
(def ^:private B [BX BY ONE (fmul BX BY)])
(def ^:private IDENT [ZERO ONE ONE ZERO])

;; ── twisted-Edwards (a=-1) complete addition; d is non-square so it doubles too ──
(defn- point-add [[X1 Y1 Z1 T1] [X2 Y2 Z2 T2]]
  (let [a (fmul (fsub Y1 X1) (fsub Y2 X2))
        b (fmul (fadd Y1 X1) (fadd Y2 X2))
        c (fmul (fmul T1 TWO-D) T2)
        dd (fmul (fmul TWO Z1) Z2)
        e (fsub b a)
        f (fsub dd c)
        g (fadd dd c)
        h (fadd b a)]
    [(fmul e f) (fmul g h) (fmul f g) (fmul e h)]))

(defn- point-mul [^BigInteger s pt]
  (loop [i (dec (.bitLength s)) q IDENT]
    (if (neg? i)
      q
      (let [q2 (point-add q q)]
        (recur (dec i) (if (.testBit s i) (point-add q2 pt) q2))))))

;; ── little-endian <-> BigInteger (32-byte) ────────────────────────────────────
(defn- le->bigint ^BigInteger [^bytes b]
  (BigInteger. 1 (byte-array (reverse (seq b)))))

(defn- bigint->le32 ^bytes [^BigInteger n]
  (let [out (byte-array 32)]
    (loop [i 0 v n]
      (if (< i 32)
        (do (aset-byte out i (unchecked-byte (.intValue (.and v (biginteger 0xff)))))
            (recur (inc i) (.shiftRight v 8)))
        out))))

;; ── compress a point → 32-byte pubkey (y little-endian, bit 255 = x parity) ───
(defn- compress ^bytes [[X Y Z _T]]
  (let [zi (finv Z)
        x  (fmul X zi)
        y  (fmul Y zi)
        out (bigint->le32 y)]
    (when (.testBit x 0)                                   ; x is odd → set sign bit
      (aset-byte out 31 (unchecked-byte (bit-or (aget out 31) 0x80))))
    out))

;; ── the derivation (RFC 8032 §5.1.5) ──────────────────────────────────────────
(defn- clamp ^bytes [^bytes h]
  (let [b (byte-array 32)]
    (System/arraycopy h 0 b 0 32)
    (aset-byte b 0  (unchecked-byte (bit-and (aget b 0) 0xf8)))   ; clear low 3 bits
    (aset-byte b 31 (unchecked-byte (bit-and (aget b 31) 0x7f)))  ; clear bit 255
    (aset-byte b 31 (unchecked-byte (bit-or  (aget b 31) 0x40)))  ; set bit 254
    b))

(defn pubkey-from-seed
  "Raw 32-byte Ed25519 seed → 32-byte PUBLIC key (RFC 8032 edwards25519)."
  ^bytes [^bytes seed]
  (when (not= 32 (count seed))
    (throw (ex-info "ed25519 seed must be exactly 32 bytes" {:got (count seed)})))
  (let [h (.digest (MessageDigest/getInstance "SHA-512") seed)
        a (le->bigint (clamp h))]
    (compress (point-mul a B))))

;; ── hex + did:key conveniences ────────────────────────────────────────────────
(defn hexify ^String [^bytes b]
  (apply str (map #(format "%02x" (bit-and (int %) 0xff)) b)))

(defn unhex ^bytes [^String s]
  (let [s (str/replace s #"\s" "")]
    (byte-array (map (fn [[a b]] (unchecked-byte (Integer/parseInt (str a b) 16)))
                     (partition 2 s)))))

(defn seed-hex->pubkey-hex
  "Hex seed → hex public key."
  ^String [^String seed-hex]
  (hexify (pubkey-from-seed (unhex seed-hex))))

(def ^:private b58-alphabet
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(defn b58
  "base58btc (Bitcoin alphabet) encode."
  ^String [^bytes b]
  (let [n (BigInteger. 1 b) fifty8 (biginteger 58)]
    (loop [n n acc ""]
      (if (pos? (.signum n))
        (recur (.divide n fifty8) (str (.charAt b58-alphabet (.intValue (.mod n fifty8))) acc))
        (str (apply str (repeat (count (take-while zero? (seq b))) \1)) acc)))))

(defn did-key-from-pub
  "Raw 32-byte Ed25519 pubkey → did:key (multicodec 0xed01 + base58btc, z-prefixed)."
  ^String [^bytes pub]
  (str "did:key:z" (b58 (byte-array (concat [(unchecked-byte 0xed) (unchecked-byte 0x01)]
                                            (seq pub))))))

(defn did-key-from-seed
  "Raw 32-byte seed → did:key:z6Mk…"
  ^String [^bytes seed]
  (did-key-from-pub (pubkey-from-seed seed)))

(defn did-key-from-seed-hex
  "Hex seed → did:key:z6Mk…"
  ^String [^String seed-hex]
  (did-key-from-seed (unhex seed-hex)))

;; ── runtime self-check via JCA (no hardcoded vector needed) ───────────────────
(def ^:private pkcs8-ed25519-prefix
  (byte-array (map unchecked-byte [0x30 0x2e 0x02 0x01 0x00 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x04 0x22 0x04 0x20])))
(def ^:private spki-ed25519-prefix
  (byte-array (map unchecked-byte [0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x03 0x21 0x00])))

(defn private-from-seed
  "Load a JCA Ed25519 PrivateKey from a raw 32-byte seed (PKCS8 wrap)."
  [^bytes seed]
  (.generatePrivate (KeyFactory/getInstance "Ed25519")
                    (PKCS8EncodedKeySpec. (byte-array (concat (seq pkcs8-ed25519-prefix) (seq seed))))))

(defn public-from-raw
  "Load a JCA Ed25519 PublicKey from a raw 32-byte pubkey (X.509 SPKI wrap)."
  [^bytes pub]
  (.generatePublic (KeyFactory/getInstance "Ed25519")
                   (X509EncodedKeySpec. (byte-array (concat (seq spki-ed25519-prefix) (seq pub))))))

(defn verify-derivation
  "Independent correctness check: sign a fixed message with the JCA PKCS8(seed)
   private key, then verify it under the pubkey THIS namespace derived. Returns
   true iff they agree — proving the derived pubkey matches the seed's true key
   without relying on any external test vector."
  [^bytes seed]
  (let [msg (.getBytes "ed25519.core self-check" "UTF-8")
        s   (doto (Signature/getInstance "Ed25519") (.initSign (private-from-seed seed)))
        _   (.update s msg)
        sig (.sign s)
        v   (doto (Signature/getInstance "Ed25519") (.initVerify (public-from-raw (pubkey-from-seed seed))))
        _   (.update v msg)]
    (.verify v sig)))
