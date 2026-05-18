package org.tron.common.utils;

import lombok.Value;

/**
 * Immutable hex-encoded post-quantum keypair (private + public key). Bundles
 * the two halves so the public/private lists can no longer drift out of
 * index-alignment by construction.
 */
@Value
public class PqKeypair {
  String privateKey;
  String publicKey;
}
