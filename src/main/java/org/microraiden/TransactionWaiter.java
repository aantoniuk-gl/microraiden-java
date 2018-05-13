package org.microraiden;

import java.io.IOException;

import org.json.simple.JSONObject;
import org.microraiden.utils.Http;

public class TransactionWaiter {
    private static final int INTERVAL_CHECK_TRANS_DONE = 100;

    private final Http httpAgent;
    private final boolean debugInfo;

    public TransactionWaiter(Http httpAgent, boolean debugInfo) {
        this.httpAgent = httpAgent;
        this.debugInfo = debugInfo;
    }

    /**
     * Waiting for the transaction to get minded
     *
     * @param transactionID - id of transaction
     * @return the blockNumber where the transaction is at
     */
    public String waitingForTransaction(String transactionID) {
        if (debugInfo) {
            System.out.println("org.microraiden.TransactionWaiter ID = " + transactionID);
        }
        boolean loop = true;
        String blockNumber = "";
        Object tempObj;
        String queryTransactionString = "{\"method\":\"eth_getTransactionReceipt\"," +
                "\"params\":[\"" +
                transactionID +
                "\"]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        while (loop) {

            try {
                tempObj = httpAgent.getHttpResponse(queryTransactionString);
            } catch (IOException e) {
                System.out.println("Fail to execute HTTP request.");
                return "";
            }
            if (tempObj == null) {
                //do nothing
            } else {
                loop = false;
                JSONObject jsonObject = (JSONObject) tempObj;
                //The jsonObject can be further parsed to get more information.
                blockNumber = (String) jsonObject.get("blockNumber");
            }
            try {
                int i = 5;
                while (i-- > 0) {
                    Thread.sleep(INTERVAL_CHECK_TRANS_DONE);
                    System.out.print("\b\\");
                    Thread.sleep(INTERVAL_CHECK_TRANS_DONE);
                    System.out.print("\b|");
                    Thread.sleep(INTERVAL_CHECK_TRANS_DONE);
                    System.out.print("\b/");
                    Thread.sleep(INTERVAL_CHECK_TRANS_DONE);
                    System.out.print("\b-");
                }
            } catch (InterruptedException e) {
            }
        }
        return blockNumber;
    }
}
