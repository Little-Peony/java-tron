package org.tron.common.crypto.pqc;

import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

public final class PQAuthSigValidator {

  private PQAuthSigValidator() {
  }

  public static boolean hasUnknownFields(PQAuthSig pqAuthSig) {
    return pqAuthSig.getUnknownFields().getSerializedSize() != 0;
  }

  public static boolean isLengthWithinBounds(PQAuthSig pqAuthSig) {
    if (hasUnknownFields(pqAuthSig)) {
      return false;
    }
    PQScheme scheme = pqAuthSig.getScheme();
    if (!PQSchemeRegistry.contains(scheme)) {
     return false;
    }
    int maxPk = PQSchemeRegistry.getPublicKeyLength(scheme);
    int maxSig = PQSchemeRegistry.getSignatureLength(scheme);
    return pqAuthSig.getPublicKey().size() <= maxPk
        && pqAuthSig.getSignature().size() <= maxSig;
  }
}
