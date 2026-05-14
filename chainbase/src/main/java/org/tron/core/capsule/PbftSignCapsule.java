package org.tron.core.capsule;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.tron.protos.Protocol.PBFTCommitResult;
import org.tron.protos.Protocol.PQAuthSig;

@Slf4j(topic = "pbft")
public class PbftSignCapsule implements ProtoCapsule<PBFTCommitResult> {

  @Getter
  private PBFTCommitResult pbftCommitResult;

  public PbftSignCapsule(byte[] data) {
    try {
      pbftCommitResult = PBFTCommitResult.parseFrom(data);
    } catch (InvalidProtocolBufferException e) {
      logger.error("", e);
    }
  }

  public PbftSignCapsule(ByteString data, List<ByteString> signList) {
    this(data, signList, Collections.emptyList());
  }

  public PbftSignCapsule(ByteString data, List<ByteString> signList,
      List<PQAuthSig> pqSignList) {
    PBFTCommitResult.Builder builder = PBFTCommitResult.newBuilder().setData(data);
    if (signList != null && !signList.isEmpty()) {
      builder.addAllSignature(signList);
    }
    if (pqSignList != null && !pqSignList.isEmpty()) {
      builder.addAllPqSignature(pqSignList);
    }
    pbftCommitResult = builder.build();
  }

  @Override
  public byte[] getData() {
    return pbftCommitResult.toByteArray();
  }

  @Override
  public PBFTCommitResult getInstance() {
    return pbftCommitResult;
  }
}