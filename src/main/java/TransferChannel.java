import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.ethereum.core.CallTransaction;
import org.ethereum.core.Transaction;
import org.ethereum.util.ByteUtil;
import org.kocakosm.pitaya.security.Digest;
import org.kocakosm.pitaya.security.Digests;

public class TransferChannel {

    private final String channelAddr;
    private final CallTransaction.Contract channelContract;
    private final BigInteger maxDeposit;
    private final Token token;
    private final BigInteger gasPrice = null;
    private final TransactionWaiter transactionWaiter;
    private final Http http;
    private final boolean debugInfo;

    public TransferChannel(String channelAddr, CallTransaction.Contract channelContract, BigInteger maxDeposit,
            Token token, Http http, boolean debugInfo) {
        this.channelAddr = channelAddr;
        this.channelContract = channelContract;
        this.maxDeposit = maxDeposit;
        this.token = token;
        this.transactionWaiter = new TransactionWaiter(http, debugInfo);
        this.http = http;
        this.debugInfo = debugInfo;
    }

    /**
     * Create a channel from sender to receiver. The sender needs to sign the transactions of approve and channel creation
     *
     * @param senderWallet      the wallet of the sender
     * @param receiverAccountId account id the receiver
     * @param deposit           the double literal as the initial deposit of the channel.
     */
    public String createChannel(Wallet senderWallet, String receiverAccountId, String deposit) {
        BigInteger initDeposit;
        try {
            initDeposit = Utility.decimalToBigInteger(deposit, token.getAppendingZerosForTKN());
        } catch (NumberFormatException e) {
            System.out.println("The provided balance is not valid.");
            return null;
        }
        if (maxDeposit.compareTo(initDeposit) < 0) {
            System.out.println("Please choose a deposit <= " + maxDeposit.toString(10));
            return null;
        }
        System.out.println("User " + senderWallet.getAccountID() + " tries to open a channel to pay " +
                receiverAccountId + " up to " + deposit + " Tokens at maximum.");

        // try to approve
        try {
            senderWallet.update(http);
        } catch (IOException e) {
            System.out.println("The sender cannot be found.");
            return null;
        }
        boolean approve = token.approve(channelAddr, senderWallet, initDeposit);
        if (!approve) return null;

        // create channel
        try {
            senderWallet.updateNonce(http);
        } catch (Exception e) {
            System.out.println("Updating nonce value is failed.");
            return null;
        }
        if (debugInfo) {
            System.out.println("The nonce of " + senderWallet.getAccountID() + " is " + senderWallet.nonce().toString(10));
        }

        CallTransaction.Function createChannelERC20 = channelContract.getByName("createChannelERC20");
        byte[] createChannelERC20FunctionBytes = createChannelERC20.encode(receiverAccountId, initDeposit);
        String queryCreatChannelGasString = "{\"method\":\"eth_estimateGas\"," +
                "\"params\":[" +
                "{" +
                "\"from\":\"" + senderWallet.getAccountID() + "\"," +
                "\"to\":\"" + channelAddr + "\"," +
                "\"value\":\"" + "0x" + new BigInteger("0", 10).toString(16) + "\"," +
                "\"data\":\"" + "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(createChannelERC20FunctionBytes)) + "\"" +
                "}" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        if (debugInfo) {
            System.out.println("The request string of queryCreatChannelGasString is " + queryCreatChannelGasString);
        }
        String creatChannelGasEstimate;
        try {
            creatChannelGasEstimate = (String) http.getHttpResponse(queryCreatChannelGasString);
        } catch (IOException e) {
            System.out.println("Invoking function with given arguments is not allowed.");
            return null;
        }

        if (debugInfo) {
            System.out.println("The estimatedGas of createChannelERC20 is " + creatChannelGasEstimate);
        }
        Transaction createTrans = new Transaction(Utility.bigIntegerToBytes(senderWallet.nonce()), // nonce
                Utility.bigIntegerToBytes(gasPrice), // gas price
                Utility.bigIntegerToBytes(new BigInteger(creatChannelGasEstimate.substring(2), 16)), // gas limit
                ByteUtil.hexStringToBytes(channelAddr), // to id
                Utility.bigIntegerToBytes(new BigInteger("0", 10)), // value
                createChannelERC20FunctionBytes, 42);// chainid
        senderWallet.signTransaction(createTrans);
        String signedChannelCreationTrans = "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(createTrans.getEncoded()));
        String createChannelSendRawTransactionString = "{\"method\":\"eth_sendRawTransaction\",\"params\":[\""
                + signedChannelCreationTrans + "\"],\"id\":42,\"jsonrpc\":\"2.0\"}";

        String myTransactionID2;
        try {
            myTransactionID2 = (String) http.getHttpResponse(createChannelSendRawTransactionString);
        } catch (IOException e) {
            System.out.println("Fail to execute HTTP request.");
            return null;
        }

        if (!"".equals(myTransactionID2)) {
            String blockNumberHex = transactionWaiter.waitingForTransaction(myTransactionID2);
            String blockNumber = new BigInteger(blockNumberHex.substring(2), 16).toString(10);

            System.out.println("\bChannel has been opened in block " + blockNumber);

            Digest keccak256 = Digests.keccak256();

            String firstArgVal = senderWallet.getAccountID().substring(2).toLowerCase();
            String secondArgVal = receiverAccountId.substring(2).toLowerCase();
            String thirdArgVal = Utility.prependingZeros(blockNumberHex.substring(2), 8);
            try {
                byte[] data = Utility.concatenateByteArrays(Hex.decodeHex(firstArgVal.toCharArray()),
                        Hex.decodeHex(secondArgVal.toCharArray()), Hex.decodeHex(thirdArgVal.toCharArray()));
                if (debugInfo) {
                    System.out.println("The keccak256 argument of bytes in string " + Hex.encodeHexString(data));
                }
                byte[] keyInBytes = keccak256.reset().update(data).digest();
                String channelKeyHex = "0x" + Hex.encodeHexString(keyInBytes);
                System.out.println("\bChannel key = " + channelKeyHex);
                System.out.println("Channel on Koven can be found on page:\nhttps://kovan.etherscan.io/address/" +
                        channelAddr + "#readContract");
            } catch (DecoderException e) {
                System.out.println("Hex string cannot be converted to byte array!");
            }
            return blockNumber;
        }
        return null;
    }

    /**
     * This function is to close the channel in a cooperative manner.
     *
     * @param delegatorWallet    the delegator's wallet used to retrieve the wallet, as the signer of the channel closing transaction.
     * @param receiverAccountId  the account id of receiver of this channel
     * @param balanceMsgHashSig  signed balance by sender
     * @param closingMsgHashSig  signed closing message by receiver
     * @param openBlockNum       the block index where the channel was open in decimal literal
     * @param balance            the double literal of the amount of taken paying to the receiver.
     */
    public void closeChannelCooperatively(Wallet delegatorWallet,
            String receiverAccountId,
            byte[] balanceMsgHashSig,
            byte[] closingMsgHashSig,
            String openBlockNum, String balance) {

        if (closingMsgHashSig == null || balanceMsgHashSig == null) {
            System.out.println("Argument Error!");
            return;
        }

        BigInteger tempBalance;
        try {
            tempBalance = Utility.decimalToBigInteger(balance, token.getAppendingZerosForTKN());
        } catch (NumberFormatException e) {
            System.out.println("The provided balance is not valid.");
            return;
        }

        try {
            delegatorWallet.update(http);
        } catch (Exception e) {
            System.out.println("The receiver cannot be found.");
            return;
        }

        if (debugInfo) {
            System.out.println("The signed closingMsgHash is 0x" + Hex.encodeHexString(closingMsgHashSig));
            System.out.println("The signed balanceMsgHash is 0x" + Hex.encodeHexString(balanceMsgHashSig));
        }
        byte[] balanceMsgHashSigR = Arrays.copyOfRange(balanceMsgHashSig, 0, 32);
        byte[] balanceMsgHashSigS = Arrays.copyOfRange(balanceMsgHashSig, 32, 64);
        byte[] balanceMsgHashSigV = Arrays.copyOfRange(balanceMsgHashSig, 64, 65);
        byte[] closingMsgHashSigR = Arrays.copyOfRange(closingMsgHashSig, 0, 32);
        byte[] closingMsgHashSigS = Arrays.copyOfRange(closingMsgHashSig, 32, 64);
        byte[] closingMsgHashSigV = Arrays.copyOfRange(closingMsgHashSig, 64, 65);

        CallTransaction.Function cooperativeClose = channelContract.getByName("cooperativeClose");
        byte[] cooperativeCloseFunctionBytes = cooperativeClose.encode(
                receiverAccountId,
                new BigInteger(openBlockNum, 10),
                tempBalance,
                balanceMsgHashSigR,
                balanceMsgHashSigS,
                new BigInteger(balanceMsgHashSigV),
                closingMsgHashSigR,
                closingMsgHashSigS,
                new BigInteger(closingMsgHashSigV));
        String querycooperativeCloseGasString = "{\"method\":\"eth_estimateGas\"," +
                "\"params\":[" +
                "{" +
                "\"from\":\"" + delegatorWallet.getAccountID() + "\"," +
                "\"to\":\"" + channelAddr + "\"," +
                "\"value\":\"" + "0x" + new BigInteger("0", 10).toString(16) + "\"," +
                "\"data\":\"" + "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(cooperativeCloseFunctionBytes)) + "\"" +
                "}" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        if (debugInfo) {
            System.out.println("The request string of querycooperativeCloseGasString is " + querycooperativeCloseGasString);
        }
        String cooperativeCloseGasEstimate;
        try {
            cooperativeCloseGasEstimate = (String) http.getHttpResponse(querycooperativeCloseGasString);
        } catch (IOException e) {
            System.out.println("Invoking function with given arguments is not allowed.");
            return;
        }
        if (debugInfo) {
            System.out.println("The estimatedGas of cooperative channel closing is " + cooperativeCloseGasEstimate + ".");
        }

        Transaction cooperativeCloseTrans = new Transaction(Utility.bigIntegerToBytes(delegatorWallet.nonce()), // nonce
                Utility.bigIntegerToBytes(gasPrice), // gas price
                Utility.bigIntegerToBytes(new BigInteger(cooperativeCloseGasEstimate.substring(2), 16)), // gas limit
                ByteUtil.hexStringToBytes(channelAddr), // to id
                Utility.bigIntegerToBytes(new BigInteger("0", 10)), // value
                cooperativeCloseFunctionBytes, 42);// chainid
        delegatorWallet.signTransaction(cooperativeCloseTrans);
        String signedCooperativeCloseTranss = "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(cooperativeCloseTrans.getEncoded()));
        String cooperativeCloseSendRawTransactionString = "{\"method\":\"eth_sendRawTransaction\",\"params\":[\""
                + signedCooperativeCloseTranss + "\"],\"id\":42,\"jsonrpc\":\"2.0\"}";

        String transactionid;
        try {
            transactionid = (String) http.getHttpResponse(cooperativeCloseSendRawTransactionString);
        } catch (IOException e) {
            System.out.println("Fail to execute HTTP request.");
            return;
        }

        if (!"".equals(transactionid)) {
            System.out.println("Waiting for Kovan to mine transactions ... ");
            transactionWaiter.waitingForTransaction(transactionid);
        }
        System.out.println("\bChannel has been closed.");
    }
}
