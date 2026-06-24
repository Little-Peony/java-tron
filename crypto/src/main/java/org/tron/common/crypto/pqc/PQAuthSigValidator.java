package org.tron.common.crypto.pqc;

import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
public final class PQAuthSigValidator {

  private PQAuthSigValidator() {
  }

  /**
   * Returns {@code true} iff the {@link PQAuthSig} carries no nested unknown
   * fields. Generated {@code PQAuthSig} retains and re-serializes unknown
   * fields, so bounding only public_key/signature would let a caller smuggle a
   * large (or simply unexpected) unknown length-delimited field while both
   * known fields stay within bounds. This is the single primitive every entry
   * point and consensus verify path uses to enforce the fixed field set.
   */
  public static boolean hasNoUnknownFields(PQAuthSig pqAuthSig) {
    return pqAuthSig.getUnknownFields().getSerializedSize() == 0;
  }

  /**
   * Returns {@code true} iff the {@link PQAuthSig} is within legal size: no
   * nested unknown fields, and public key / signature within the declared
   * scheme's maximum. A registered scheme uses its exact per-scheme maximum; an
   * unknown/future scheme falls back to the global maximum across all
   * registered schemes, so memory stays bounded without rejecting
   * forward-compatible peers.
   *
   * <p>The unknown-field check matters because generated {@code PQAuthSig}
   * retains and re-serializes unknown fields: bounding only public_key/signature
   * would let a caller smuggle a large unknown length-delimited field while both
   * known fields stay within bounds. PQAuthSig's field set is fixed
   * (scheme/public_key/signature), so rejecting unknown fields is safe.
   */
  public static boolean isLengthWithinBounds(PQAuthSig pqAuthSig) {
    if (!hasNoUnknownFields(pqAuthSig)) {
      return false;
    }
    PQScheme scheme = pqAuthSig.getScheme();
    int maxPk;
    int maxSig;
    if (PQSchemeRegistry.contains(scheme)) {
      maxPk = PQSchemeRegistry.getPublicKeyLength(scheme);
      maxSig = PQSchemeRegistry.getSignatureLength(scheme);
    } else {
      maxPk = PQSchemeRegistry.getMaxPublicKeyLength();
      maxSig = PQSchemeRegistry.getMaxSignatureLength();
    }
    return pqAuthSig.getPublicKey().size() <= maxPk
        && pqAuthSig.getSignature().size() <= maxSig;
  }
}
