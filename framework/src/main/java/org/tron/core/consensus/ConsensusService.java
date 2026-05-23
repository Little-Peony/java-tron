package org.tron.core.consensus;

import static org.tron.common.utils.ByteArray.fromHexString;

import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.common.parameter.CommonParameter;
import org.tron.consensus.Consensus;
import org.tron.consensus.base.Param;
import org.tron.consensus.base.Param.Miner;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.exception.TronError;
import org.tron.core.store.WitnessStore;
import org.tron.protos.Protocol.PQScheme;

@Slf4j(topic = "consensus")
@Component
public class ConsensusService {

  @Autowired
  private Consensus consensus;

  @Autowired
  private WitnessStore witnessStore;

  @Autowired
  private BlockHandleImpl blockHandle;

  @Autowired
  private PbftBaseImpl pbftBaseImpl;

  private CommonParameter parameter = Args.getInstance();

  public void start() {
    Param param = Param.getInstance();
    param.setEnable(parameter.isWitness());
    param.setGenesisBlock(parameter.getGenesisBlock());
    param.setMinParticipationRate(parameter.getMinParticipationRate());
    param.setBlockProduceTimeoutPercent(Args.getInstance().getBlockProducedTimeOut());
    param.setNeedSyncCheck(parameter.isNeedSyncCheck());
    param.setAgreeNodeCount(parameter.getAgreeNodeCount());
    List<Miner> miners = new ArrayList<>();
    List<String> privateKeys = Args.getLocalWitnesses().getPrivateKeys();
    List<PqKeypair> pqKeypairs = Args.getLocalWitnesses().getPqKeypairs();

    if (privateKeys.size() > 1) {
      for (String key : privateKeys) {
        byte[] privateKey = fromHexString(key);
        byte[] privateKeyAddress = SignUtils
            .fromPrivate(privateKey, Args.getInstance().isECKeyCryptoEngine()).getAddress();
        WitnessCapsule witnessCapsule = witnessStore.get(privateKeyAddress);
        if (null == witnessCapsule) {
          logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(privateKeyAddress));
        }
        Miner miner = param.new Miner(privateKey, ByteString.copyFrom(privateKeyAddress),
            ByteString.copyFrom(privateKeyAddress));
        miners.add(miner);
        logger.info("Add witness: {}, size: {}",
            Hex.toHexString(privateKeyAddress), miners.size());
      }
    } else if (privateKeys.size() == 1) {
      byte[] privateKey =
          fromHexString(Args.getLocalWitnesses().getPrivateKey());
      byte[] privateKeyAddress = SignUtils.fromPrivate(privateKey,
          Args.getInstance().isECKeyCryptoEngine()).getAddress();
      byte[] witnessAddress = Args.getLocalWitnesses().getWitnessAccountAddress();
      // In mixed (ECDSA + PQ) mode Args refuses the localWitnessAccountAddress
      // override and leaves witnessAccountAddress null — fall back to the
      // derived address so the single-witness path stays valid.
      if (witnessAddress == null || witnessAddress.length == 0) {
        witnessAddress = privateKeyAddress;
      }
      WitnessCapsule witnessCapsule = witnessStore.get(witnessAddress);
      if (null == witnessCapsule) {
        logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(witnessAddress));
      }
      // In multi-signature mode, the address derived from the private key may differ from
      // witnessAddress.
      Miner miner = param.new Miner(privateKey, ByteString.copyFrom(privateKeyAddress),
          ByteString.copyFrom(witnessAddress));
      miners.add(miner);
    }

    if (pqKeypairs.size() > 1) {
      for (PqKeypair kp : pqKeypairs) {
        PQScheme scheme = kp.getScheme();
        requireSupportedPqScheme(scheme);
        byte[] privBytes = fromHexString(kp.getPrivateKey());
        byte[] pubBytes = fromHexString(kp.getPublicKey());
        PQSignature keypair = PQSchemeRegistry.fromKeypair(scheme, privBytes, pubBytes);
        byte[] sk = keypair.getPrivateKey();
        byte[] pk = keypair.getPublicKey();
        byte[] pqAddress = keypair.getAddress();
        WitnessCapsule witnessCapsule = witnessStore.get(pqAddress);
        if (null == witnessCapsule) {
          logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(pqAddress));
        }
        ByteString pqAddressBs = ByteString.copyFrom(pqAddress);
        Miner miner = param.new Miner(null, pqAddressBs, pqAddressBs);
        miner.setPQPrivateKey(sk);
        miner.setPQPublicKey(pk);
        miner.setPqScheme(scheme);
        miners.add(miner);
        logger.info("Add {} witness (from configured keypair): {}, size: {}",
            scheme, Hex.toHexString(pqAddress), miners.size());
      }
    } else if (pqKeypairs.size() == 1) {
      miners.add(buildPQOnlyMinerFromKeypair(param, pqKeypairs.get(0)));
    }

    param.setMiners(miners);
    param.setBlockHandle(blockHandle);
    param.setPbftInterface(pbftBaseImpl);
    consensus.start(param);
    logger.info("consensus service start success");
  }

  private Miner buildPQOnlyMinerFromKeypair(Param param, PqKeypair pqKeypair) {
    PQScheme scheme = pqKeypair.getScheme();
    requireSupportedPqScheme(scheme);
    byte[] privBytes = fromHexString(pqKeypair.getPrivateKey());
    byte[] pubBytes = fromHexString(pqKeypair.getPublicKey());
    PQSignature keypair = PQSchemeRegistry.fromKeypair(scheme, privBytes, pubBytes);
    byte[] sk = keypair.getPrivateKey();
    byte[] pk = keypair.getPublicKey();
    byte[] pqAddress = keypair.getAddress();
    byte[] witnessAddress = Args.getLocalWitnesses().getWitnessAccountAddress();
    if (witnessAddress == null || witnessAddress.length == 0) {
      witnessAddress = pqAddress;
    }
    WitnessCapsule witnessCapsule = witnessStore.get(witnessAddress);
    if (null == witnessCapsule) {
      logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(witnessAddress));
    }
    // In multi-signature mode, the address derived from the PQ key may differ from witnessAddress.
    Miner miner = param.new Miner(null, ByteString.copyFrom(pqAddress),
        ByteString.copyFrom(witnessAddress));
    miner.setPQPrivateKey(sk);
    miner.setPQPublicKey(pk);
    miner.setPqScheme(scheme);
    logger.info("Add {} witness (from configured keypair): {}",
        scheme, Hex.toHexString(witnessAddress));
    return miner;
  }

  private static void requireSupportedPqScheme(PQScheme scheme) {
    if (!PQSchemeRegistry.contains(scheme)) {
      throw new TronError("unsupported PQ witness scheme: " + scheme,
          TronError.ErrCode.WITNESS_INIT);
    }
  }

  public void stop() {
    logger.info("consensus service closed start.");
    consensus.stop();
    logger.info("consensus service closed successfully.");
  }

}
