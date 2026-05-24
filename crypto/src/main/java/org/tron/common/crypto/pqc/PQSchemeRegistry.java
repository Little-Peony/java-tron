package org.tron.common.crypto.pqc;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import org.tron.common.crypto.Hash;
import org.tron.protos.Protocol.PQScheme;

/**
 * Static dispatch table for post-quantum signature schemes keyed by
 * {@link PQScheme}. Each entry binds a scheme to its public-key length,
 * signature length, seed length, fingerprint hash function, and stateless
 * sign/verify/keygen operations. Legacy ECDSA secp256k1 / SM2 schemes are NOT
 * registered — they flow through the existing {@code SignInterface} path.
 *
 * <p><b>Address binding (V2).</b> A PQ-derived TRON address is
 * {@code 0x41 ‖ deriveHash(scheme, public_key)[12..32]}, matching the ECDSA
 * flow's {@code 0x41 ‖ Keccak-256(public_key)[12..32]} so PQ and ECDSA
 * addresses share the same derivation shape. The hash function is scheme-
 * specific (see {@link #deriveHash}); {@code FN_DSA_512} and {@code ML_DSA_44}
 * both use Keccak-256.
 *
 * <p><b>Wire format.</b> The proto3 default {@code UNKNOWN_PQ_SCHEME = 0} is
 * reserved for the {@code UNKNOWN_} API-evolution slot and is NOT interpreted
 * as any registered scheme — producers must set the scheme tag explicitly so
 * future schemes can be added without ambiguity between "client did not set
 * scheme" and "client meant FN_DSA_512". {@link #contains}/{@link #require}
 * reject {@code UNKNOWN_PQ_SCHEME} on the same path as {@code UNRECOGNIZED}.
 */
public final class PQSchemeRegistry {

  /** Stateless sign/verify/keygen dispatch bound to a single PQ scheme. */
  public interface SignatureOps {
    byte[] sign(byte[] privateKey, byte[] message);

    boolean verify(byte[] publicKey, byte[] message, byte[] signature);

    PQSignature fromSeed(byte[] seed);

    PQSignature fromKeypair(byte[] privateKey, byte[] publicKey);
  }

  /**
   * Fingerprint hash used to derive a 21-byte TRON address from a PQ public key.
   * V2 first launch uses Keccak-256 for FN_DSA_512 to match the ECDSA address
   * derivation; later schemes may bind to a different hash if the PQ scheme has
   * its own canonical fingerprint.
   */
  public interface FingerprintHash {
    /** Returns the full digest of {@code data} (no truncation). */
    byte[] digest(byte[] data);
  }

  private static final FingerprintHash KECCAK_256 = Hash::sha3;

  private static final class SchemeInfo {
    final int privateKeyLength;
    final int publicKeyLength;
    final int signatureLength;
    // Lower bound of the signature-length band. Equal to signatureLength for
    // fixed-length schemes (Dilithium); strictly less for variable-length
    // schemes (Falcon). Mirrors PQSignature#getSignatureMinLength.
    final int signatureMinLength;
    final int seedLength;
    // Whether seed -> (priv, pub) derivation is bit-for-bit reproducible
    // across platforms. Falcon's reference keygen uses FFT and is not stable
    // across JVMs/architectures, so operators must persist the expanded
    // priv‖pub rather than a seed.
    final boolean seedDeterministic;
    final FingerprintHash hash;
    final SignatureOps ops;

    SchemeInfo(int privateKeyLength, int publicKeyLength, int signatureLength,
        int signatureMinLength, int seedLength, boolean seedDeterministic,
        FingerprintHash hash, SignatureOps ops) {
      this.privateKeyLength = privateKeyLength;
      this.publicKeyLength = publicKeyLength;
      this.signatureLength = signatureLength;
      this.signatureMinLength = signatureMinLength;
      this.seedLength = seedLength;
      this.seedDeterministic = seedDeterministic;
      this.hash = hash;
      this.ops = ops;
    }
  }

  private static final Map<PQScheme, SchemeInfo> SCHEMES;

  static {
    EnumMap<PQScheme, SchemeInfo> m = new EnumMap<>(PQScheme.class);
    m.put(PQScheme.FN_DSA_512, new SchemeInfo(
        FNDSA512.PRIVATE_KEY_LENGTH, FNDSA512.PUBLIC_KEY_LENGTH,
        FNDSA512.SIGNATURE_LENGTH, FNDSA512.SIGNATURE_MIN_LENGTH,
        FNDSA512.SEED_LENGTH,
        false, // Falcon keygen is FFT-based, not bit-stable across platforms.
        KECCAK_256,
        new SignatureOps() {
          @Override
          public byte[] sign(byte[] privateKey, byte[] message) {
            return FNDSA512.sign(privateKey, message);
          }

          @Override
          public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return FNDSA512.verify(publicKey, message, signature);
          }

          @Override
          public PQSignature fromSeed(byte[] seed) {
            return new FNDSA512(seed);
          }

          @Override
          public PQSignature fromKeypair(byte[] privateKey, byte[] publicKey) {
            return new FNDSA512(privateKey, publicKey);
          }
        }));
    m.put(PQScheme.ML_DSA_44, new SchemeInfo(
        MLDSA44.PRIVATE_KEY_LENGTH, MLDSA44.PUBLIC_KEY_LENGTH,
        MLDSA44.SIGNATURE_LENGTH, MLDSA44.SIGNATURE_LENGTH, // fixed-length scheme
        MLDSA44.SEED_LENGTH,
        true, // FIPS-204 keygen is pure integer arithmetic and reproducible.
        KECCAK_256,
        new SignatureOps() {
          @Override
          public byte[] sign(byte[] privateKey, byte[] message) {
            return MLDSA44.sign(privateKey, message);
          }

          @Override
          public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return MLDSA44.verify(publicKey, message, signature);
          }

          @Override
          public PQSignature fromSeed(byte[] seed) {
            return new MLDSA44(seed);
          }

          @Override
          public PQSignature fromKeypair(byte[] privateKey, byte[] publicKey) {
            return new MLDSA44(privateKey, publicKey);
          }
        }));
    SCHEMES = Collections.unmodifiableMap(m);
  }

  private PQSchemeRegistry() {
  }

  /**
   * Pass-through for API stability. {@code UNKNOWN_PQ_SCHEME} is no longer
   * normalized to {@code FN_DSA_512}; producers must set the scheme tag
   * explicitly. {@code null} and {@code UNRECOGNIZED} pass through unchanged
   * so the caller-side {@code contains}/{@code require} checks reject them.
   */
  public static PQScheme resolve(PQScheme scheme) {
    return scheme;
  }

  public static boolean contains(PQScheme scheme) {
    if (scheme == null || scheme == PQScheme.UNKNOWN_PQ_SCHEME) {
      return false;
    }
    return SCHEMES.containsKey(scheme);
  }

  /**
   * Returns the set of post-quantum schemes that are registered (i.e. have an
   * active {@link SignatureOps} entry). Lets governance / config layers
   * enumerate "all PQ schemes" without hard-coding the list — adding a new
   * scheme to the registry then auto-propagates to any caller iterating over
   * this set.
   */
  public static Set<PQScheme> registeredSchemes() {
    return SCHEMES.keySet();
  }

  public static int getPrivateKeyLength(PQScheme scheme) {
    return require(scheme).privateKeyLength;
  }

  public static int getPublicKeyLength(PQScheme scheme) {
    return require(scheme).publicKeyLength;
  }

  public static int getSignatureLength(PQScheme scheme) {
    return require(scheme).signatureLength;
  }

  public static int getSeedLength(PQScheme scheme) {
    return require(scheme).seedLength;
  }

  /**
   * Whether seed -> keypair derivation is bit-for-bit reproducible across
   * platforms. Operators may safely persist a seed (instead of the expanded
   * priv‖pub) only when this is {@code true}; otherwise different JVMs /
   * architectures may derive divergent private keys from the same seed.
   */
  public static boolean isSeedDeterministic(PQScheme scheme) {
    return require(scheme).seedDeterministic;
  }

  /**
   * Per-scheme signature-length predicate. Each scheme carries its own band
   * {@code [signatureMinLength, signatureLength]}; fixed-length schemes
   * degenerate to the singleton {@code [max, max]}. Mirrors
   * {@link PQSignature#validateSignature} so adding a new variable-length
   * scheme requires no edit here.
   */
  public static boolean isValidSignatureLength(PQScheme scheme, int length) {
    SchemeInfo info = require(scheme);
    return length >= info.signatureMinLength && length <= info.signatureLength;
  }

  /** Lower bound of the per-scheme signature-length band. */
  public static int getSignatureMinLength(PQScheme scheme) {
    return require(scheme).signatureMinLength;
  }

  public static byte[] sign(PQScheme scheme, byte[] privateKey, byte[] message) {
    return require(scheme).ops.sign(privateKey, message);
  }

  public static boolean verify(
      PQScheme scheme, byte[] publicKey, byte[] message, byte[] signature) {
    return require(scheme).ops.verify(publicKey, message, signature);
  }

  public static PQSignature fromSeed(PQScheme scheme, byte[] seed) {
    return require(scheme).ops.fromSeed(seed);
  }

  /**
   * Build a keypair-bound {@link PQSignature} from already-derived private and
   * public key bytes. Used by the witness-config path when the operator has
   * pre-computed the keypair off-line and wants to bypass on-node keygen.
   * Validates {@code privateKey} and {@code publicKey} lengths against the
   * scheme; cryptographic consistency between the two halves is the caller's
   * responsibility.
   */
  public static PQSignature fromKeypair(
      PQScheme scheme, byte[] privateKey, byte[] publicKey) {
    return require(scheme).ops.fromKeypair(privateKey, publicKey);
  }

  /**
   * Scheme-dispatched fingerprint hash of a PQ public key. Returns the full
   * digest; callers truncate to 20 bytes when deriving the address suffix.
   */
  public static byte[] deriveHash(PQScheme scheme, byte[] publicKey) {
    SchemeInfo info = require(scheme);
    if (publicKey == null || publicKey.length != info.publicKeyLength) {
      throw new IllegalArgumentException(
          "invalid public key length for " + scheme + ": "
              + (publicKey == null ? -1 : publicKey.length));
    }
    return info.hash.digest(publicKey);
  }

  /**
   * Derive the 21-byte TRON address from a PQ public key as
   * {@code 0x41 ‖ deriveHash(scheme, public_key)[12..32]} — the rightmost 20
   * bytes of the digest, matching the ECDSA address derivation slice.
   */
  public static byte[] computeAddress(PQScheme scheme, byte[] publicKey) {
    byte[] h = deriveHash(scheme, publicKey);
    byte[] addr = new byte[21];
    addr[0] = 0x41;
    System.arraycopy(h, h.length - 20, addr, 1, 20);
    return addr;
  }

  private static SchemeInfo require(PQScheme scheme) {
    if (scheme == null) {
      throw new IllegalArgumentException("scheme must not be null");
    }
    if (scheme == PQScheme.UNKNOWN_PQ_SCHEME) {
      throw new IllegalArgumentException(
          "no PQSignature registered for scheme: " + scheme);
    }
    SchemeInfo info = SCHEMES.get(scheme);
    if (info == null) {
      throw new IllegalArgumentException(
          "no PQSignature registered for scheme: " + scheme);
    }
    return info;
  }
}
