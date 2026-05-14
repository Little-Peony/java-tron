package org.tron.consensus.pbft.message;

import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.SignatureException;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.overlay.message.Message;
import org.tron.common.utils.ByteUtil;
import org.tron.common.utils.Sha256Hash;
import org.tron.common.utils.StringUtil;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.exception.P2pException;
import org.tron.protos.Protocol.PBFTMessage;
import org.tron.protos.Protocol.PBFTMessage.DataType;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;
import org.tron.protos.Protocol.SRL;

public abstract class PbftBaseMessage extends Message {

  protected PBFTMessage pbftMessage;

  private boolean isSwitch;

  private byte[] publicKey;

  public PbftBaseMessage() {
  }

  public PbftBaseMessage(byte type, byte[] data) throws IOException, P2pException {
    super(type, data);
    this.pbftMessage = PBFTMessage.parseFrom(getCodedInputStream(data));
    if (isFilter()) {
      compareBytes(data, pbftMessage.toByteArray());
    }
  }

  @Override
  public Class<?> getAnswerMessage() {
    return null;
  }

  public PBFTMessage getPbftMessage() {
    return pbftMessage;
  }

  public PbftBaseMessage setPbftMessage(PBFTMessage pbftMessage) {
    this.pbftMessage = pbftMessage;
    return this;
  }

  public boolean isSwitch() {
    return isSwitch;
  }

  public PbftBaseMessage setSwitch(boolean aSwitch) {
    isSwitch = aSwitch;
    return this;
  }

  public PbftBaseMessage setData(byte[] data) {
    this.data = data;
    return this;
  }

  public PbftBaseMessage setType(byte type) {
    this.type = type;
    return this;
  }

  public byte[] getPublicKey() {
    return publicKey;
  }

  public String getKey() {
    return getNo() + "_" + Hex.toHexString(publicKey);
  }

  public String getDataKey() {
    return getNo() + "_" + Hex.toHexString(pbftMessage.getRawData().getData().toByteArray());
  }

  public long getNumber() {
    return pbftMessage.getRawData().getViewN();
  }

  public long getEpoch() {
    return pbftMessage.getRawData().getEpoch();
  }

  public DataType getDataType() {
    return pbftMessage.getRawData().getDataType();
  }

  public abstract String getNo();

  public void analyzeSignature() throws SignatureException {
    byte[] hash = Sha256Hash.hash(true, getPbftMessage().getRawData().toByteArray());
    boolean hasLegacy = !getPbftMessage().getSignature().isEmpty();
    boolean hasPq = getPbftMessage().hasPqAuthSig();
    if (hasLegacy == hasPq) {
      throw new SignatureException(
          "pbft message must set exactly one of signature / pq_auth_sig");
    }
    if (hasPq) {
      publicKey = verifyPqAuthSig(hash, getPbftMessage().getPqAuthSig());
    } else {
      publicKey = ECKey.signatureToAddress(hash, TransactionCapsule
          .getBase64FromByteString(getPbftMessage().getSignature()));
    }
  }

  private static byte[] verifyPqAuthSig(byte[] hash, PQAuthSig pqAuthSig)
      throws SignatureException {
    PQScheme scheme = pqAuthSig.getScheme();
    if (!PQSchemeRegistry.contains(scheme)) {
      throw new SignatureException("pbft pq_auth_sig scheme not registered: " + scheme);
    }
    byte[] publicKey = pqAuthSig.getPublicKey().toByteArray();
    if (publicKey.length != PQSchemeRegistry.getPublicKeyLength(scheme)) {
      throw new SignatureException("pbft pq_auth_sig public key length mismatch for " + scheme);
    }
    byte[] signature = pqAuthSig.getSignature().toByteArray();
    if (!PQSchemeRegistry.isValidSignatureLength(scheme, signature.length)) {
      throw new SignatureException("pbft pq_auth_sig signature length mismatch for " + scheme);
    }
    if (!PQSchemeRegistry.verify(scheme, publicKey, hash, signature)) {
      throw new SignatureException("pbft pq_auth_sig verification failed for " + scheme);
    }
    return PQSchemeRegistry.computeAddress(scheme, publicKey);
  }

  @Override
  public String toString() {
    return "DataType:" + getDataType() + ", MsgType:" + pbftMessage.getRawData().getMsgType()
        + ", node address:" + (ByteUtil.isNullOrZeroArray(publicKey) ? null
        : Hex.toHexString(publicKey))
        + ", viewN:" + pbftMessage.getRawData().getViewN()
        + ", epoch:" + pbftMessage.getRawData().getEpoch()
        + ", data:" + getDataString()
        + ", " + super.toString();
  }

  public String getDataString() {
    return getDataType() == DataType.SRL ? decode()
        : Hex.toHexString(pbftMessage.getRawData().getData().toByteArray());
  }

  private String decode() {
    try {
      SRL srList = SRL.parseFrom(pbftMessage.getRawData().getData().toByteArray());
      return "sr list = " + srList.getSrAddressList().stream().map(
          bytes -> StringUtil.encode58Check(bytes.toByteArray())).collect(Collectors.toList());
    } catch (InvalidProtocolBufferException e) {
    }
    return "decode error";
  }
}
