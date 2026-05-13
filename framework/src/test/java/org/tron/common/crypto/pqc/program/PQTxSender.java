package org.tron.common.crypto.pqc.program;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import org.tron.api.GrpcAPI.EmptyMessage;
import org.tron.api.GrpcAPI.Return;
import org.tron.api.WalletGrpc;
import org.tron.api.WalletGrpc.WalletBlockingStub;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.math.StrictMathWrapper;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Commons;
import org.tron.common.utils.StringUtil;
import org.tron.common.utils.client.utils.AbiUtil;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.BalanceContract.TransferContract;
import org.tron.protos.contract.SmartContractOuterClass.TriggerSmartContract;

/**
 * Demo client that connects to {@link PQWitnessNode} and continuously broadcasts FN-DSA-512 signed
 * transfer and TRC20 transactions at 10 TPS.
 * <p>
 * The keypair is derived from the same fixed seed used by PQWitnessNode, so no out-of-band key
 * exchange is needed.
 * <p>
 * Run from the repository root:
 *   ./gradlew :framework:buildFullNodeJar :framework:compileTestJava
 *   java -Dpqc.host=127.0.0.1 -Dpqc.port=50051 -Dpqc.transfer.tps=10 -Dpqc.trc20.tps=10 \
 *     -cp "framework/build/classes/java/test:framework/build/resources/test:\
 *          framework/build/libs/FullNode.jar" \
 *     org.tron.common.crypto.pqc.program.PQTxSender
 *
 * Optional JVM args:
 *   -Dpqc.host=localhost
 *   -Dpqc.port=50051
 *   -Dpqc.transfer.tps=10
 *   -Dpqc.trc20.tps=10
 */
public class PQTxSender {

  private static final String HOST =
      System.getProperty("pqc.host", "localhost");
  private static final int PORT =
      Integer.parseInt(System.getProperty("pqc.port", "50051"));

  /**
   * Recipient of the demo transfer.
   */
  private static final byte[] TO_ADDR =
      Commons.decodeFromBase58Check("T9zNBvTFD97XzGsjGqvg2QHizTG8sibsHt");

  /**
   * TRC20 contract address (USDT on TRON).
   */
  private static final byte[] TRC20_CONTRACT_ADDR =
      Commons.decodeFromBase58Check("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");

  /**
   * Demo TRC20 amount in base units (6 decimals = 1 token).
   */
  private static final long TRC20_AMOUNT = 1L;

  /**
   * Upper bound for TRC20 execution fee.
   */
  private static final long TRC20_FEE_LIMIT = 1000_000_000L;

  /**
   * Default send rate for transfer transactions.
   */
  private static final double DEFAULT_TRANSFER_TPS = 10.0d;
  /**
   * Default send rate for TRC20 transactions.
   */
  private static final double DEFAULT_TRC20_TPS = 10.0d;

  public static void main(String[] args) throws Exception {
    // Force INFO level: logback-test.xml (on the test classpath) sets root=DEBUG
    // which is far too noisy for a demo run.
    ((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
        .getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME))
        .setLevel(ch.qos.logback.classic.Level.INFO);

    // ── 1. Derive user keypair from same fixed seed as PQWitnessNode ─────
    byte[] userSeed = new byte[FNDSA512.SEED_LENGTH];
    Arrays.fill(userSeed, (byte) 0x02);
    FNDSA512 userKp = new FNDSA512(userSeed);

    byte[] userPub = userKp.getPublicKey();
    byte[] userPriv = userKp.getPrivateKey();
    byte[] signerAddr = FNDSA512.computeAddress(userPub);
    byte[] ownerAddr = Commons.decodeFromBase58Check("TJUfbazhixG4YtqJxUDmv5XisZvvy1wP91");
    double transferTps = readTps("pqc.transfer.tps", DEFAULT_TRANSFER_TPS);
    double trc20Tps = readTps("pqc.trc20.tps", DEFAULT_TRC20_TPS);

    System.out.println("=== PQC Client ===");
    System.out.println("Connecting to " + HOST + ":" + PORT);
    System.out.println("Owner address:  " + ByteArray.toHexString(ownerAddr));
    System.out.println("Signer address: " + ByteArray.toHexString(signerAddr));
    System.out.println("Transfer TPS:   " + transferTps);
    System.out.println("TRC20 TPS:      " + trc20Tps);

    // ── 2. Connect via gRPC ───────────────────────────────────────────────
    ManagedChannel channel = ManagedChannelBuilder
        .forAddress(HOST, PORT)
        .usePlaintext()
        .build();
    WalletBlockingStub stub = WalletGrpc.newBlockingStub(channel);

    try {
      Thread transferThread = new Thread(
          () -> runTransferLoop(stub, ownerAddr, userPub, userPriv, transferTps),
          "pqc-transfer-sender-grpc");
      Thread trc20Thread = new Thread(
          () -> runTrc20Loop(stub, ownerAddr, userPub, userPriv, trc20Tps),
          "pqc-trc20-sender-grpc");

      transferThread.start();
      trc20Thread.start();
      transferThread.join();
      trc20Thread.join();
    } finally {
      channel.shutdown();
      channel.awaitTermination(5, TimeUnit.SECONDS);
    }
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static byte[] longToBytes(long value) {
    return ByteBuffer.allocate(8).putLong(value).array();
  }

  private static void runTransferLoop(WalletBlockingStub stub, byte[] ownerAddr,
      byte[] userPub, byte[] userPriv, double tps) {
    if (tps <= 0) {
      System.out.println("transfer sender disabled");
      return;
    }
    long intervalMs = tpsToIntervalMs(tps);
    long counter = 1L;
    while (!Thread.currentThread().isInterrupted()) {
      long loopStart = System.currentTimeMillis();
      sendTransferTransaction(stub, ownerAddr, userPub, userPriv, counter++);
      sleepRemaining(intervalMs, loopStart);
    }
  }

  private static void runTrc20Loop(WalletBlockingStub stub, byte[] ownerAddr,
      byte[] userPub, byte[] userPriv, double tps) {
    if (tps <= 0) {
      System.out.println("trc20 sender disabled");
      return;
    }
    long intervalMs = tpsToIntervalMs(tps);
    long counter = 1L;
    while (!Thread.currentThread().isInterrupted()) {
      long loopStart = System.currentTimeMillis();
      sendTrc20Transaction(stub, ownerAddr, userPub, userPriv, counter++);
      sleepRemaining(intervalMs, loopStart);
    }
  }

  private static void sendTransferTransaction(WalletBlockingStub stub, byte[] ownerAddr,
      byte[] userPub, byte[] userPriv, long seq) {
    try {
      WalletBlockingStub timedStub = stub.withDeadlineAfter(10, TimeUnit.SECONDS);

      // Fetch the latest block for TaPoS before every send so the demo stays valid
      // even if the node advances quickly.
      Block head = timedStub.getNowBlock(EmptyMessage.getDefaultInstance());
      byte[] headerRaw = head.getBlockHeader().getRawData().toByteArray();
      long refNum = head.getBlockHeader().getRawData().getNumber();
      byte[] blockHash = sha256(headerRaw);

      Transaction tx = buildTransferTransaction(ownerAddr, blockHash, refNum);
      byte[] txId = sha256(tx.getRawData().toByteArray());
      byte[] sig = FNDSA512.sign(userPriv, txId);
      Transaction signedTx = tx.toBuilder()
          .addPqAuthSig(PQAuthSig.newBuilder()
              .setPublicKey(ByteString.copyFrom(userPub))
              .setSignature(ByteString.copyFrom(sig)))
          .build();

      Return result = timedStub.broadcastTransaction(signedTx);
      System.out.println("[transfer-" + seq + "] ref=#" + refNum
          + " tx=" + ByteArray.toHexString(txId)
          + " result=" + result.getCode()
          + " msg=" + result.getMessage().toStringUtf8());
    } catch (Exception e) {
      System.err.println("[transfer-" + seq + "] send failed: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  private static void sendTrc20Transaction(WalletBlockingStub stub, byte[] ownerAddr,
      byte[] userPub, byte[] userPriv, long seq) {
    try {
      WalletBlockingStub timedStub = stub.withDeadlineAfter(10, TimeUnit.SECONDS);

      // Fetch the latest block for TaPoS before every send so the demo stays valid
      // even if the node advances quickly.
      Block head = timedStub.getNowBlock(EmptyMessage.getDefaultInstance());
      byte[] headerRaw = head.getBlockHeader().getRawData().toByteArray();
      long refNum = head.getBlockHeader().getRawData().getNumber();
      byte[] blockHash = sha256(headerRaw);

      Transaction tx = buildTrc20Transaction(ownerAddr, blockHash, refNum);
      Transaction.raw.Builder rawBuilder = tx.getRawData().toBuilder();
      rawBuilder.setFeeLimit(TRC20_FEE_LIMIT);
      tx = tx.toBuilder().setRawData(rawBuilder).build();

      byte[] txId = sha256(tx.getRawData().toByteArray());
      byte[] sig = FNDSA512.sign(userPriv, txId);
      Transaction signedTx = tx.toBuilder()
          .addPqAuthSig(PQAuthSig.newBuilder()
              .setPublicKey(ByteString.copyFrom(userPub))
              .setSignature(ByteString.copyFrom(sig)))
          .build();

      Return result = timedStub.broadcastTransaction(signedTx);
      System.out.println("[trc20-" + seq + "] ref=#" + refNum
          + " tx=" + ByteArray.toHexString(txId)
          + " result=" + result.getCode()
          + " msg=" + result.getMessage().toStringUtf8());
    } catch (Exception e) {
      System.err.println("[trc20-" + seq + "] send failed: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  private static Transaction buildTransferTransaction(byte[] ownerAddr, byte[] blockHash,
      long refNum) {
    Transaction.raw rawData = Transaction.raw.newBuilder()
        .addContract(Transaction.Contract.newBuilder()
            .setType(ContractType.TransferContract)
            .setParameter(Any.pack(TransferContract.newBuilder()
                .setOwnerAddress(ByteString.copyFrom(ownerAddr))
                .setToAddress(ByteString.copyFrom(TO_ADDR))
                .setAmount(1000L)
                .build()))
            .setPermissionId(0))
        .setRefBlockHash(ByteString.copyFrom(Arrays.copyOfRange(blockHash, 8, 16)))
        .setRefBlockBytes(ByteString.copyFrom(longToBytes(refNum), 6, 2))
        .setExpiration(System.currentTimeMillis() + 60_000L)
        .build();
    return Transaction.newBuilder().setRawData(rawData).build();
  }

  private static Transaction buildTrc20Transaction(byte[] ownerAddr, byte[] blockHash,
      long refNum) {
    String callData = AbiUtil.parseMethod("transfer(address,uint256)",
        Arrays.asList(StringUtil.encode58Check(TO_ADDR), Long.toString(TRC20_AMOUNT)));
    TriggerSmartContract trigger = TriggerSmartContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(ownerAddr))
        .setContractAddress(ByteString.copyFrom(TRC20_CONTRACT_ADDR))
        .setData(ByteString.copyFrom(ByteArray.fromHexString(callData)))
        .setCallValue(0L)
        .build();
    TransactionCapsule trxCap = new TransactionCapsule(trigger, ContractType.TriggerSmartContract);
    Transaction tx = trxCap.getInstance();
    Transaction.raw.Builder rawBuilder = tx.getRawData().toBuilder();
    rawBuilder.setRefBlockHash(ByteString.copyFrom(Arrays.copyOfRange(blockHash, 8, 16)));
    rawBuilder.setRefBlockBytes(ByteString.copyFrom(longToBytes(refNum), 6, 2));
    rawBuilder.setExpiration(System.currentTimeMillis() + 60_000L);
    return tx.toBuilder().setRawData(rawBuilder).build();
  }

  private static double readTps(String key, double defaultValue) {
    return Double.parseDouble(System.getProperty(key, Double.toString(defaultValue)));
  }

  private static long tpsToIntervalMs(double tps) {
    return StrictMathWrapper.max(1L, StrictMathWrapper.round(1000.0d / tps));
  }

  private static void sleepRemaining(long intervalMs, long loopStartMs) {
    long sleepMs = intervalMs - (System.currentTimeMillis() - loopStartMs);
    if (sleepMs > 0) {
      try {
        Thread.sleep(sleepMs);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
  }
}
