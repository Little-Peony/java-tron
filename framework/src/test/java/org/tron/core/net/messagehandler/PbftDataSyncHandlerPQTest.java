package org.tron.core.net.messagehandler;

import com.google.protobuf.ByteString;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.utils.Sha256Hash;
import org.tron.consensus.base.Param;
import org.tron.core.ChainBaseManager;
import org.tron.core.store.DynamicPropertiesStore;
import org.tron.protos.Protocol.PBFTMessage.DataType;
import org.tron.protos.Protocol.PBFTMessage.MsgType;
import org.tron.protos.Protocol.PBFTMessage.Raw;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

/**
 * Focused tests for {@link PbftDataSyncHandler#validPbftSign} covering PQ and
 * mixed ECDSA/PQ quorums on the commit-sync path.
 */
public class PbftDataSyncHandlerPQTest {

  private PbftDataSyncHandler handler;
  private ChainBaseManager chainBaseManager;
  private DynamicPropertiesStore dynamicPropertiesStore;
  private int previousAgreeNodeCount;
  private boolean previousEnable;

  @Before
  public void setUp() throws Exception {
    handler = new PbftDataSyncHandler();
    chainBaseManager = Mockito.mock(ChainBaseManager.class);
    dynamicPropertiesStore = Mockito.mock(DynamicPropertiesStore.class);
    Mockito.when(chainBaseManager.getDynamicPropertiesStore()).thenReturn(dynamicPropertiesStore);
    Mockito.when(dynamicPropertiesStore.isPqSchemeAllowed(PQScheme.FN_DSA_512)).thenReturn(true);
    Mockito.when(dynamicPropertiesStore.isPqSchemeAllowed(PQScheme.UNKNOWN_PQ_SCHEME))
        .thenReturn(false);

    java.lang.reflect.Field field = PbftDataSyncHandler.class.getDeclaredField("chainBaseManager");
    field.setAccessible(true);
    field.set(handler, chainBaseManager);

    previousAgreeNodeCount = Param.getInstance().getAgreeNodeCount();
    previousEnable = Param.getInstance().isEnable();
  }

  @After
  public void tearDown() {
    Param.getInstance().setAgreeNodeCount(previousAgreeNodeCount);
    Param.getInstance().setEnable(previousEnable);
    handler.close();
  }

  @Test
  public void emptySignatureListsValidate() throws Exception {
    Param.getInstance().setAgreeNodeCount(1);
    Raw raw = buildRaw(1);
    Assert.assertTrue(invokeValid(raw, Collections.emptyList(), Collections.emptyList(),
        Collections.emptyList()));
  }

  @Test
  public void pqQuorumValidates() throws Exception {
    Param.getInstance().setAgreeNodeCount(2);
    Raw raw = buildRaw(1);
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());

    FNDSA512 kp1 = new FNDSA512();
    FNDSA512 kp2 = new FNDSA512();
    PQAuthSig sig1 = pqSign(kp1, hash);
    PQAuthSig sig2 = pqSign(kp2, hash);

    List<ByteString> witnesses = Arrays.asList(
        pqAddress(kp1),
        pqAddress(kp2));

    Assert.assertTrue(invokeValid(raw, Collections.emptyList(),
        Arrays.asList(sig1, sig2), witnesses));
  }

  @Test
  public void mixedEcdsaAndPqQuorumValidates() throws Exception {
    Param.getInstance().setAgreeNodeCount(2);
    Raw raw = buildRaw(2);
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());

    ECKey ec = new ECKey();
    byte[] ecSig = ec.sign(hash).toByteArray();

    FNDSA512 kp = new FNDSA512();
    PQAuthSig pq = pqSign(kp, hash);

    List<ByteString> witnesses = Arrays.asList(
        ByteString.copyFrom(ec.getAddress()),
        pqAddress(kp));

    Assert.assertTrue(invokeValid(raw,
        Collections.singletonList(ByteString.copyFrom(ecSig)),
        Collections.singletonList(pq),
        witnesses));
  }

  @Test
  public void underQuorumFails() throws Exception {
    Param.getInstance().setAgreeNodeCount(3);
    Raw raw = buildRaw(3);
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());

    FNDSA512 kp = new FNDSA512();
    PQAuthSig pq = pqSign(kp, hash);
    List<ByteString> witnesses = Collections.singletonList(
        pqAddress(kp));

    Assert.assertFalse(invokeValid(raw, Collections.emptyList(),
        Collections.singletonList(pq), witnesses));
  }

  @Test
  public void pqSchemeNotActivatedFails() throws Exception {
    Param.getInstance().setAgreeNodeCount(1);
    Raw raw = buildRaw(4);
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());

    FNDSA512 kp = new FNDSA512();
    PQAuthSig pq = pqSign(kp, hash);
    List<ByteString> witnesses = Collections.singletonList(
        pqAddress(kp));

    Mockito.when(dynamicPropertiesStore.isPqSchemeAllowed(PQScheme.FN_DSA_512)).thenReturn(false);
    Assert.assertFalse(invokeValid(raw, Collections.emptyList(),
        Collections.singletonList(pq), witnesses));
  }

  @Test
  public void pqPublicKeyLengthMismatchFails() throws Exception {
    Param.getInstance().setAgreeNodeCount(1);
    Raw raw = buildRaw(5);
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());

    FNDSA512 kp = new FNDSA512();
    byte[] sig = PQSchemeRegistry.sign(PQScheme.FN_DSA_512, kp.getPrivateKey(), hash);
    PQAuthSig pq = PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(new byte[FNDSA512.PUBLIC_KEY_LENGTH - 1]))
        .setSignature(ByteString.copyFrom(sig))
        .build();
    List<ByteString> witnesses = Collections.singletonList(
        pqAddress(kp));

    Assert.assertFalse(invokeValid(raw, Collections.emptyList(),
        Collections.singletonList(pq), witnesses));
  }

  @Test
  public void pqSignerNotInWitnessSetFails() throws Exception {
    Param.getInstance().setAgreeNodeCount(1);
    Raw raw = buildRaw(6);
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());

    FNDSA512 kp = new FNDSA512();
    PQAuthSig pq = pqSign(kp, hash);
    FNDSA512 stranger = new FNDSA512();
    List<ByteString> witnesses = Collections.singletonList(pqAddress(stranger));

    Assert.assertFalse(invokeValid(raw, Collections.emptyList(),
        Collections.singletonList(pq), witnesses));
  }

  @Test
  public void duplicatePqSignerDoesNotInflateQuorum() throws Exception {
    Param.getInstance().setAgreeNodeCount(2);
    Raw raw = buildRaw(8);
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());

    FNDSA512 kp = new FNDSA512();
    PQAuthSig sig1 = pqSign(kp, hash);
    PQAuthSig sig2 = pqSign(kp, hash);
    Assert.assertNotEquals("Falcon should produce randomized signatures",
        sig1.getSignature(), sig2.getSignature());

    List<ByteString> witnesses = Collections.singletonList(
        pqAddress(kp));

    Assert.assertFalse(invokeValid(raw, Collections.emptyList(),
        Arrays.asList(sig1, sig2), witnesses));
  }

  @Test
  public void pqBadSignatureFails() throws Exception {
    Param.getInstance().setAgreeNodeCount(1);
    Raw raw = buildRaw(7);
    byte[] hash = Sha256Hash.hash(true, raw.toByteArray());

    FNDSA512 kp = new FNDSA512();
    byte[] goodSig = PQSchemeRegistry.sign(PQScheme.FN_DSA_512, kp.getPrivateKey(), hash);
    byte[] tampered = Arrays.copyOf(goodSig, goodSig.length);
    tampered[tampered.length - 1] ^= 0x01;
    PQAuthSig pq = PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
        .setSignature(ByteString.copyFrom(tampered))
        .build();
    List<ByteString> witnesses = Collections.singletonList(
        pqAddress(kp));

    Assert.assertFalse(invokeValid(raw, Collections.emptyList(),
        Collections.singletonList(pq), witnesses));
  }

  private static Raw buildRaw(long viewN) {
    return Raw.newBuilder()
        .setViewN(viewN)
        .setEpoch(0)
        .setDataType(DataType.BLOCK)
        .setMsgType(MsgType.COMMIT)
        .setData(ByteString.copyFromUtf8("payload-" + viewN))
        .build();
  }

  private static ByteString pqAddress(FNDSA512 kp) {
    return ByteString.copyFrom(
        PQSchemeRegistry.computeAddress(PQScheme.FN_DSA_512, kp.getPublicKey()));
  }

  private static PQAuthSig pqSign(FNDSA512 kp, byte[] hash) {
    byte[] sig = PQSchemeRegistry.sign(PQScheme.FN_DSA_512, kp.getPrivateKey(), hash);
    return PQAuthSig.newBuilder()
        .setScheme(PQScheme.FN_DSA_512)
        .setPublicKey(ByteString.copyFrom(kp.getPublicKey()))
        .setSignature(ByteString.copyFrom(sig))
        .build();
  }

  private boolean invokeValid(Raw raw, List<ByteString> srSignList,
      List<PQAuthSig> pqSignList, List<ByteString> witnesses) throws Exception {
    Method m = PbftDataSyncHandler.class.getDeclaredMethod("validPbftSign",
        Raw.class, List.class, List.class, List.class);
    m.setAccessible(true);
    return (Boolean) m.invoke(handler, raw, new ArrayList<>(srSignList),
        new ArrayList<>(pqSignList), witnesses);
  }
}
