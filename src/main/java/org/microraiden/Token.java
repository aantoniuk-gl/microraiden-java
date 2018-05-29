package org.microraiden;

import java.io.IOException;
import java.math.BigInteger;

import org.apache.commons.codec.binary.Hex;
import org.ethereum.core.CallTransaction;
import org.ethereum.core.Transaction;
import org.ethereum.util.ByteUtil;
import org.microraiden.utils.Http;
import org.microraiden.utils.Utility;

public class Token {

    private final CallTransaction.Contract tokenContract;
    private final String tokenAddr;
    private final String appendingZerosForTKN;
    private final String appendingZerosForETH;
    private final BigInteger gasPrice;
    private final Http httpAgent;
    private final boolean debugInfo;
    private final TransactionWaiter transactionWaiter;

    public Token(String tokenABI, String tokenAddr, String appendingZerosForTKN,
            String appendingZerosForETH, BigInteger gasPrice, Http httpAgent, boolean debugInfo) {
        this.tokenContract = new CallTransaction.Contract(tokenABI);
        this.tokenAddr = tokenAddr;
        this.appendingZerosForTKN = appendingZerosForTKN;
        this.appendingZerosForETH = appendingZerosForETH;
        this.gasPrice = gasPrice;
        this.httpAgent = httpAgent;
        this.debugInfo = debugInfo;
        this.transactionWaiter = new TransactionWaiter(httpAgent, debugInfo);
    }

    public String getAppendingZerosForTKN() {
        return appendingZerosForTKN;
    }

    public String balanceOf(String accountId) {

        CallTransaction.Function balanceOf = tokenContract.getByName("balanceOf");
        byte[] functionBytes = balanceOf.encode(accountId);
        String requestString = "{\"method\":\"eth_call\"," +
                "\"params\":[" +
                "{" +
                "\"to\":\"" + tokenAddr + "\"," +
                "\"data\":\"" + "0x" + new String(Hex.encodeHex(functionBytes)) + "\"" +
                "}," +
                "\"latest\"" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        if (debugInfo) {
            System.out.println("Request in getTokenBalance = " + requestString);
        }
        String myTokenBalance;
        try {
            myTokenBalance = (String) httpAgent.getHttpResponse(requestString);
        } catch (IOException e) {
            System.out.println("Cannot get token balance for " + accountId);
            return null;
        }
        System.out.println("Balance of " + accountId + " = " +
                Double.toString(
                        new BigInteger(myTokenBalance.substring(2), 16).doubleValue() /
                                (new BigInteger(appendingZerosForTKN, 10).doubleValue())) + " TKN");
        return myTokenBalance;
    }

    public void mint(Wallet wallet, String amountOfEther) {
        BigInteger value;
        try {
            value = Utility.decimalToBigInteger(amountOfEther, appendingZerosForETH);
        } catch (NumberFormatException e) {
            System.out.println("The provided balance is not valid.");
            return;
        }

        if (debugInfo) {
            System.out.println("User(" + wallet.getAccountID() + ") will trade " + value.toString() + " Wei to org.microraiden.Token.");
        }

        CallTransaction.Function mint = tokenContract.getByName("mint");
        byte[] functionBytes = mint.encode();
        String queryGasString = "{\"method\":\"eth_estimateGas\"," +
                "\"params\":[" +
                "{" +
                "\"from\":\"" + wallet.getAccountID() + "\"," +
                "\"to\":\"" + tokenAddr + "\"," +
                "\"value\":\"" + "0x" + value.toString(16) + "\"," +
                "\"data\":\"" + "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(functionBytes)) + "\"" +
                "}" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        String gasEstimateResult;
        try {
            gasEstimateResult = (String) httpAgent.getHttpResponse(queryGasString);
        } catch (IOException e) {
            System.out.println("Invoking function with given arguments is not allowed.");
            return;
        }
        if (debugInfo) {
            System.out.println("The estimatedGas of mint is " + gasEstimateResult);
        }

        if (debugInfo) {
            System.out.println("Total ether balance of " + wallet.getAccountID() + " is " + wallet.etherBalance().toString(10));
        }
        if (new BigInteger(gasEstimateResult.substring(2), 16).multiply(gasPrice).add(value).compareTo(wallet.etherBalance()) > 0) {
            System.out.println("Insufficient Ether to finish the transaction.");
            return;
        }

        if (debugInfo) {
            System.out.println("The nonce of " + wallet.getAccountID() + " is " + wallet.nonce());
        }

        Transaction t = new Transaction(Utility.bigIntegerToBytes(wallet.nonce()), // nonce
                Utility.bigIntegerToBytes(gasPrice), // gas price
                Utility.bigIntegerToBytes(new BigInteger(gasEstimateResult.substring(2), 16)), // gas limit
                ByteUtil.hexStringToBytes(tokenAddr), // to id
                Utility.bigIntegerToBytes(value), // value
                functionBytes, 42);// chainid
        wallet.signTransaction(t);
        String signedTrans = "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(t.getEncoded()));
        String mintSendRawTransactionString = "{\"method\":\"eth_sendRawTransaction\",\"params\":[\""
                + signedTrans + "\"],\"id\":42,\"jsonrpc\":\"2.0\"}";

        String myTransactionID;
        try {
            myTransactionID = (String) httpAgent.getHttpResponse(mintSendRawTransactionString);
        } catch (IOException e) {
            System.out.println("Fail to execute HTTP request.");
            return;
        }

        if (!"".equals(myTransactionID)) {
            System.out.println("Waiting for Kovan to mine transactions ... ");
            transactionWaiter.waitingForTransaction(myTransactionID);
        }
        System.out.println("\bYou have been given 50 tokens.");
    }

    /**
     * Approve sender to transfer some amount of tokens to any address.
     *
     * @param channelAddr
     * @param senderWallet
     * @param amount
     * @return boolean      true if is approved, false if not
     */
    public boolean approve(String channelAddr, Wallet senderWallet, BigInteger amount) {

        CallTransaction.Function approve = tokenContract.getByName("approve");
        byte[] approveFunctionBytes = approve.encode(channelAddr, amount);
        String queryApproveGasString = "{\"method\":\"eth_estimateGas\"," +
                "\"params\":[" +
                "{" +
                "\"from\":\"" + senderWallet.getAccountID() + "\"," +
                "\"to\":\"" + tokenAddr + "\"," +
                "\"value\":\"" + "0x" + new BigInteger("0", 10).toString(16) + "\"," +
                "\"data\":\"" + "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(approveFunctionBytes)) + "\"" +
                "}" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        if (debugInfo) {
            System.out.println("The request string of queryApproveGasString is " + queryApproveGasString);
        }
        String approveGasEstimate;
        try {
            approveGasEstimate = (String) httpAgent.getHttpResponse(queryApproveGasString);
        } catch (IOException e) {
            System.out.println("Invoking function with given arguments is not allowed.");
            return false;
        }
        if (debugInfo) {
            System.out.println("The estimatedGas of approve is " + approveGasEstimate + ".");
            System.out.println("The nonce of " + senderWallet.getAccountID() + " is " + senderWallet.nonce().toString(10));
        }

        Transaction approveTrans = new Transaction(Utility.bigIntegerToBytes(senderWallet.nonce()), // nonce
                Utility.bigIntegerToBytes(gasPrice), // gas price
                Utility.bigIntegerToBytes(new BigInteger(approveGasEstimate.substring(2), 16)), // gas limit
                ByteUtil.hexStringToBytes(tokenAddr), // to id
                Utility.bigIntegerToBytes(new BigInteger("0", 10)), // value
                approveFunctionBytes, 42);// chainid
        senderWallet.signTransaction(approveTrans);
        String signedApproveTrans = "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(approveTrans.getEncoded()));
        String approveSendRawTransactionString = "{\"method\":\"eth_sendRawTransaction\",\"params\":[\""
                + signedApproveTrans + "\"],\"id\":42,\"jsonrpc\":\"2.0\"}";

        String transactionId;
        try {
            transactionId = (String) httpAgent.getHttpResponse(approveSendRawTransactionString);
        } catch (IOException e) {
            System.out.println("Fail to execute HTTP request.");
            return false;
        }

        if (!"".equals(transactionId)) {
            System.out.println("Waiting for Kovan to mine transactions ... ");
            transactionWaiter.waitingForTransaction(transactionId);
        }
        if (debugInfo) {
            System.out.println("\bApproving funding transfer is done.");
        }
        return true;
    }
}
