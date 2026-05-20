package org.tron.common.crypto.pqc;

import lombok.ToString;
import lombok.Value;

/**
 * Immutable hex-encoded post-quantum keypair (private + public key). Bundles
 * the two halves so the public/private lists can no longer drift out of
 * index-alignment by construction.
 *
 * <p>{@code privateKey} is excluded from {@link #toString()} to prevent
 * accidental leakage of secret-key material into logs.
 */
@Value
public class PqKeypair {
  @ToString.Exclude
  String privateKey;
  String publicKey;
}
