package org.tron.core.net.messagehandler;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Sets;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.netty.util.internal.ConcurrentSet;
import java.io.Closeable;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.es.ExecutorServiceManager;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Sha256Hash;
import org.tron.consensus.base.Param;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.db.PbftSignDataStore;
import org.tron.core.exception.P2pException;
import org.tron.core.net.message.TronMessage;
import org.tron.core.net.message.pbft.PbftCommitMessage;
import org.tron.core.net.peer.PeerConnection;
import org.tron.protos.Protocol.PBFTMessage.DataType;
import org.tron.protos.Protocol.PBFTMessage.Raw;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.PQScheme;

@Slf4j(topic = "pbft-data-sync")
@Service
public class PbftDataSyncHandler implements TronMsgHandler, Closeable {

  private static final Cache<Long, PbftCommitMessage> pbftCommitMessageCache =
      CacheBuilder.newBuilder().initialCapacity(100).maximumSize(200)
          .expireAfterWrite(10, TimeUnit.MINUTES).build();

  private final String esName = "valid-header-pbft-sign";

  private ExecutorService executorService = ExecutorServiceManager.newFixedThreadPool(
      esName, 19);

  @Autowired
  private ChainBaseManager chainBaseManager;

  @Override
  public void processMessage(PeerConnection peer, TronMessage msg) throws P2pException {
    PbftCommitMessage pbftCommitMessage = (PbftCommitMessage) msg;
    try {
      if (!chainBaseManager.getDynamicPropertiesStore().allowPBFT()) {
        return;
      }
      Raw raw = Raw.parseFrom(pbftCommitMessage.getPBFTCommitResult().getData());
      pbftCommitMessageCache.put(raw.getViewN(), pbftCommitMessage);
    } catch (InvalidProtocolBufferException e) {
      logger.error("", e);
    }
  }

  public void processPBFTCommitData(BlockCapsule block) {
    try {
      if (!chainBaseManager.getDynamicPropertiesStore().allowPBFT()) {
        return;
      }
      long epoch = 0;
      PbftCommitMessage pbftCommitMessage = pbftCommitMessageCache.getIfPresent(block.getNum());
      pbftCommitMessageCache.invalidate(block.getNum());
      long maintenanceTimeInterval = chainBaseManager.getDynamicPropertiesStore()
          .getMaintenanceTimeInterval();
      if (pbftCommitMessage == null) {
        long round = block.getTimeStamp() / maintenanceTimeInterval;
        epoch = (round + 1) * maintenanceTimeInterval;
      } else {
        processPBFTCommitMessage(pbftCommitMessage);
        Raw raw = Raw.parseFrom(pbftCommitMessage.getPBFTCommitResult().getData());
        epoch = raw.getEpoch();
      }
      pbftCommitMessage = pbftCommitMessageCache.getIfPresent(epoch);
      pbftCommitMessageCache.invalidate(epoch);
      if (pbftCommitMessage != null) {
        processPBFTCommitMessage(pbftCommitMessage);
      }
    } catch (Exception e) {
      logger.error("", e);
    }
  }

  @Override
  public void close() {
    ExecutorServiceManager.shutdownAndAwaitTermination(executorService, esName);
  }

  private void processPBFTCommitMessage(PbftCommitMessage pbftCommitMessage) {
    try {
      PbftSignDataStore pbftSignDataStore = chainBaseManager.getPbftSignDataStore();
      Raw raw = Raw.parseFrom(pbftCommitMessage.getPBFTCommitResult().getData());
      if (!validPbftSign(raw, pbftCommitMessage.getPBFTCommitResult().getSignatureList(),
          pbftCommitMessage.getPBFTCommitResult().getPqSignatureList(),
          chainBaseManager.getWitnesses())) {
        return;
      }
      if (raw.getDataType() == DataType.BLOCK
          && pbftSignDataStore.getBlockSignData(raw.getViewN()) == null) {
        pbftSignDataStore.putBlockSignData(raw.getViewN(), pbftCommitMessage.getPbftSignCapsule());
        logger.info("Save the block {} pbft commit data", raw.getViewN());
      } else if (raw.getDataType() == DataType.SRL
          && pbftSignDataStore.getSrSignData(raw.getEpoch()) == null) {
        pbftSignDataStore.putSrSignData(raw.getEpoch(), pbftCommitMessage.getPbftSignCapsule());
        logger.info("Save the srl {} pbft commit data", raw.getEpoch());
      }
    } catch (InvalidProtocolBufferException e) {
      logger.error("", e);
    }
  }

  private boolean validPbftSign(Raw raw, List<ByteString> srSignList,
      List<PQAuthSig> pqSignList, List<ByteString> currentSrList) {
    int totalSigs = srSignList.size() + pqSignList.size();
    if (totalSigs == 0) {
      return true;
    }
    Set<ByteString> srSignSet = new ConcurrentSet();
    srSignSet.addAll(srSignList);
    Set<ByteString> pqSignSet = new ConcurrentSet();
    for (PQAuthSig pqSign : pqSignList) {
      pqSignSet.add(pqSign.toByteString());
    }
    int uniqueSigs = srSignSet.size() + pqSignSet.size();
    if (uniqueSigs < Param.getInstance().getAgreeNodeCount()) {
      logger.error("sr sign count {} < sr count * 2/3 + 1 == {}", uniqueSigs,
          Param.getInstance().getAgreeNodeCount());
      return false;
    }
    byte[] dataHash = Sha256Hash.hash(true, raw.toByteArray());
    Set<ByteString> srSet = Sets.newHashSet(currentSrList);
    List<Future<Boolean>> futureList = new ArrayList<>();
    for (ByteString sign : srSignList) {
      futureList.add(executorService.submit(
          new ValidPbftSignTask(raw.getViewN(), srSignSet, dataHash, srSet, sign)));
    }
    for (PQAuthSig pqSign : pqSignList) {
      futureList.add(executorService.submit(
          new ValidPqPbftSignTask(raw.getViewN(), pqSignSet, dataHash, srSet, pqSign)));
    }
    for (Future<Boolean> future : futureList) {
      try {
        if (!future.get()) {
          return false;
        }
      } catch (Exception e) {
        logger.error("", e);
      }
    }
    return srSignSet.isEmpty() && pqSignSet.isEmpty();
  }

  private class ValidPbftSignTask implements Callable<Boolean> {

    private long viewN;
    private Set<ByteString> srSignSet;
    private byte[] dataHash;
    private Set<ByteString> srSet;
    private ByteString sign;

    ValidPbftSignTask(long viewN, Set<ByteString> srSignSet,
        byte[] dataHash, Set<ByteString> srSet, ByteString sign) {
      this.viewN = viewN;
      this.srSignSet = srSignSet;
      this.dataHash = dataHash;
      this.srSet = srSet;
      this.sign = sign;
    }

    @Override
    public Boolean call() throws Exception {
      try {
        byte[] srAddress = ECKey.signatureToAddress(dataHash,
            TransactionCapsule.getBase64FromByteString(sign));
        if (!srSet.contains(ByteString.copyFrom(srAddress))) {
          logger.error("valid sr signature fail,error sr address:{}",
              ByteArray.toHexString(srAddress));
          return false;
        }
        srSignSet.remove(sign);
      } catch (SignatureException e) {
        logger.error("viewN {} valid sr list sign fail!", viewN, e);
        return false;
      }
      return true;
    }
  }

  private class ValidPqPbftSignTask implements Callable<Boolean> {

    private final long viewN;
    private final Set<ByteString> pqSignSet;
    private final byte[] dataHash;
    private final Set<ByteString> srSet;
    private final PQAuthSig pqAuthSig;

    ValidPqPbftSignTask(long viewN, Set<ByteString> pqSignSet,
        byte[] dataHash, Set<ByteString> srSet, PQAuthSig pqAuthSig) {
      this.viewN = viewN;
      this.pqSignSet = pqSignSet;
      this.dataHash = dataHash;
      this.srSet = srSet;
      this.pqAuthSig = pqAuthSig;
    }

    @Override
    public Boolean call() {
      PQScheme scheme = pqAuthSig.getScheme();
      if (!chainBaseManager.getDynamicPropertiesStore().isPqSchemeAllowed(scheme)) {
        logger.error("viewN {} pq scheme {} not activated on chain", viewN, scheme);
        return false;
      }
      if (!PQSchemeRegistry.contains(scheme)) {
        logger.error("viewN {} pq scheme {} not registered locally", viewN, scheme);
        return false;
      }
      byte[] publicKey = pqAuthSig.getPublicKey().toByteArray();
      if (publicKey.length != PQSchemeRegistry.getPublicKeyLength(scheme)) {
        logger.error("viewN {} pq public key length mismatch for {}", viewN, scheme);
        return false;
      }
      byte[] signature = pqAuthSig.getSignature().toByteArray();
      if (!PQSchemeRegistry.isValidSignatureLength(scheme, signature.length)) {
        logger.error("viewN {} pq signature length mismatch for {}", viewN, scheme);
        return false;
      }
      if (!PQSchemeRegistry.verify(scheme, publicKey, dataHash, signature)) {
        logger.error("viewN {} pq signature verification failed for {}", viewN, scheme);
        return false;
      }
      byte[] srAddress = PQSchemeRegistry.computeAddress(scheme, publicKey);
      if (!srSet.contains(ByteString.copyFrom(srAddress))) {
        logger.error("valid sr pq signature fail, error sr address:{}",
            ByteArray.toHexString(srAddress));
        return false;
      }
      pqSignSet.remove(pqAuthSig.toByteString());
      return true;
    }
  }

}
