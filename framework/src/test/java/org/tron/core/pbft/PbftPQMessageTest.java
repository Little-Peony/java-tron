package org.tron.core.pbft;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.protobuf.ByteString;
import java.security.SignatureException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;
import org.tron.consensus.base.Param;
import org.tron.consensus.base.Param.Miner;
import org.tron.consensus.base.Param.MinerType;
import org.tron.consensus.pbft.message.PbftMessage;
import org.tron.core.capsule.BlockCapsule;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.PBFTMessage;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

public class PbftPQMessageTest {

  private static Miner pqMiner(FNDSA512 kp) {
    byte[] address = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, kp.getPublicKey());
    ByteString addressBs = ByteString.copyFrom(address);
    Miner miner = Param.getInstance().new Miner(null, addressBs, addressBs);
    miner.setPQPrivateKey(kp.getPrivateKey());
    miner.setPQPublicKey(kp.getPublicKey());
    miner.setPqScheme(PQScheme.FN_DSA_512);
    miner.setType(MinerType.PQ);
    return miner;
  }

  private static Miner ecdsaMiner() {
    ECKey key = new ECKey();
    ByteString addressBs = ByteString.copyFrom(key.getAddress());
    return Param.getInstance().new Miner(
        key.getPrivKeyBytes(), addressBs, addressBs);
  }

  private static BlockCapsule emptyBlock() {
    return new BlockCapsule(Block.getDefaultInstance());
  }

  /** ECDSA path is unchanged: analyzeSignature recovers the signer address. */
  @Test
  public void testEcdsaHappyPath() throws Exception {
    Miner miner = ecdsaMiner();
    PbftMessage msg = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);
    assertFalse(msg.getPbftMessage().getSignature().isEmpty());
    assertFalse(msg.getPbftMessage().hasPqAuthSig());
    msg.analyzeSignature();
    assertArrayEquals(miner.getWitnessAddress().toByteArray(), msg.getPublicKey());
  }

  /** PQ miner produces a pbft message with pq_auth_sig populated and signature cleared. */
  @Test
  public void testPqHappyPath() throws Exception {
    FNDSA512 kp = new FNDSA512();
    Miner miner = pqMiner(kp);

    PbftMessage msg = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);
    assertTrue(msg.getPbftMessage().getSignature().isEmpty());
    assertTrue(msg.getPbftMessage().hasPqAuthSig());
    PQAuthSig pqAuthSig = msg.getPbftMessage().getPqAuthSig();
    assertEquals(PQScheme.FN_DSA_512, pqAuthSig.getScheme());
    assertArrayEquals(kp.getPublicKey(), pqAuthSig.getPublicKey().toByteArray());

    msg.analyzeSignature();
    assertArrayEquals(miner.getWitnessAddress().toByteArray(), msg.getPublicKey());
  }

  /** PREPARE / COMMIT round-trip also signs with the PQ key. */
  @Test
  public void testPqPrepareAndCommit() throws Exception {
    FNDSA512 kp = new FNDSA512();
    Miner miner = pqMiner(kp);
    PbftMessage pre = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);

    PbftMessage prepare = pre.buildPrePareMessage(miner);
    assertTrue(prepare.getPbftMessage().hasPqAuthSig());
    prepare.analyzeSignature();
    assertArrayEquals(miner.getWitnessAddress().toByteArray(), prepare.getPublicKey());

    PbftMessage commit = pre.buildCommitMessage(miner);
    assertTrue(commit.getPbftMessage().hasPqAuthSig());
    commit.analyzeSignature();
    assertArrayEquals(miner.getWitnessAddress().toByteArray(), commit.getPublicKey());
  }

  /** Both signature and pq_auth_sig present → reject. */
  @Test
  public void testMutexBothSet() throws Exception {
    FNDSA512 kp = new FNDSA512();
    Miner miner = pqMiner(kp);
    PbftMessage msg = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);

    PBFTMessage tampered = msg.getPbftMessage().toBuilder()
        .setSignature(ByteString.copyFrom(new byte[65]))
        .build();
    PbftMessage rebuilt = rebuild(msg, tampered);
    SignatureException ex = assertThrows(SignatureException.class, rebuilt::analyzeSignature);
    assertTrue(ex.getMessage().contains("exactly one"));
  }

  /** Neither signature nor pq_auth_sig present → reject. */
  @Test
  public void testMutexNeitherSet() throws Exception {
    Miner miner = ecdsaMiner();
    PbftMessage msg = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);

    PBFTMessage tampered = msg.getPbftMessage().toBuilder()
        .clearSignature()
        .clearPqAuthSig()
        .build();
    PbftMessage rebuilt = rebuild(msg, tampered);
    SignatureException ex = assertThrows(SignatureException.class, rebuilt::analyzeSignature);
    assertTrue(ex.getMessage().contains("exactly one"));
  }

  /** Scheme not registered → reject. */
  @Test
  public void testPqSchemeNotRegistered() throws Exception {
    FNDSA512 kp = new FNDSA512();
    Miner miner = pqMiner(kp);
    PbftMessage msg = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);

    // UNKNOWN_PQ_SCHEME (0) is normalized to FN_DSA_512 by PQSchemeRegistry#resolve
    // for proto3 default-zero compatibility, so use setSchemeValue() to inject a
    // truly unrecognized scheme value that bypasses the enum and the normalizer.
    PBFTMessage tampered = msg.getPbftMessage().toBuilder()
        .setPqAuthSig(msg.getPbftMessage().getPqAuthSig().toBuilder()
            .setSchemeValue(999))
        .build();
    PbftMessage rebuilt = rebuild(msg, tampered);
    SignatureException ex = assertThrows(SignatureException.class, rebuilt::analyzeSignature);
    assertTrue(ex.getMessage().contains("scheme not registered"));
  }

  /** Public-key length mismatch → reject. */
  @Test
  public void testPqBadPublicKeyLength() throws Exception {
    FNDSA512 kp = new FNDSA512();
    Miner miner = pqMiner(kp);
    PbftMessage msg = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);

    byte[] shortPk = new byte[FNDSA512.PUBLIC_KEY_LENGTH - 1];
    PBFTMessage tampered = msg.getPbftMessage().toBuilder()
        .setPqAuthSig(msg.getPbftMessage().getPqAuthSig().toBuilder()
            .setPublicKey(ByteString.copyFrom(shortPk)))
        .build();
    PbftMessage rebuilt = rebuild(msg, tampered);
    SignatureException ex = assertThrows(SignatureException.class, rebuilt::analyzeSignature);
    assertTrue(ex.getMessage().contains("public key length mismatch"));
  }

  /** Signature length above protocol cap → reject. */
  @Test
  public void testPqBadSignatureLength() throws Exception {
    FNDSA512 kp = new FNDSA512();
    Miner miner = pqMiner(kp);
    PbftMessage msg = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);

    byte[] oversized = new byte[FNDSA512.SIGNATURE_LENGTH + 1];
    PBFTMessage tampered = msg.getPbftMessage().toBuilder()
        .setPqAuthSig(msg.getPbftMessage().getPqAuthSig().toBuilder()
            .setSignature(ByteString.copyFrom(oversized)))
        .build();
    PbftMessage rebuilt = rebuild(msg, tampered);
    SignatureException ex = assertThrows(SignatureException.class, rebuilt::analyzeSignature);
    assertTrue(ex.getMessage().contains("signature length mismatch"));
  }

  /** Public key replaced with a stray keypair → verify fails. */
  @Test
  public void testPqSignatureFromWrongKey() throws Exception {
    FNDSA512 kp = new FNDSA512();
    Miner miner = pqMiner(kp);
    PbftMessage msg = PbftMessage.prePrepareBlockMsg(emptyBlock(), 1, miner);

    FNDSA512 stranger = new FNDSA512();
    PBFTMessage tampered = msg.getPbftMessage().toBuilder()
        .setPqAuthSig(msg.getPbftMessage().getPqAuthSig().toBuilder()
            .setPublicKey(ByteString.copyFrom(stranger.getPublicKey())))
        .build();
    PbftMessage rebuilt = rebuild(msg, tampered);
    SignatureException ex = assertThrows(SignatureException.class, rebuilt::analyzeSignature);
    assertTrue(ex.getMessage().contains("verification failed"));
  }

  /** Hand-built PQ signature recovers the derived witness address. */
  @Test
  public void testManualPqAuthSig() throws Exception {
    FNDSA512 kp = new FNDSA512();
    byte[] expected = PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, kp.getPublicKey());

    PBFTMessage.Raw raw = PBFTMessage.Raw.newBuilder()
        .setViewN(1)
        .setEpoch(1)
        .setDataType(PBFTMessage.DataType.BLOCK)
        .setMsgType(PBFTMessage.MsgType.PREPREPARE)
        .setData(ByteString.copyFrom(ByteArray.fromHexString("abcd")))
        .build();
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());
    byte[] sig = PQSchemeRegistry.sign(PQScheme.FN_DSA_512, kp.getPrivateKey(), hash);

    PBFTMessage message = PBFTMessage.newBuilder()
        .setRawData(raw)
        .setPqAuthSig(PQAuthSig.newBuilder()
            .setScheme(PQScheme.FN_DSA_512)
            .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
            .setSignature(ByteString.copyFrom(sig)))
        .build();
    PbftMessage pbft = new PbftMessage();
    pbft.setPbftMessage(message);
    pbft.setData(message.toByteArray());
    pbft.analyzeSignature();
    assertEquals(Hex.toHexString(expected), Hex.toHexString(pbft.getPublicKey()));
  }

  private static PbftMessage rebuild(PbftMessage original, PBFTMessage replacement) {
    PbftMessage rebuilt = new PbftMessage();
    rebuilt.setType(original.getType().asByte());
    rebuilt.setPbftMessage(replacement);
    rebuilt.setData(replacement.toByteArray());
    rebuilt.setSwitch(original.isSwitch());
    return rebuilt;
  }
}
