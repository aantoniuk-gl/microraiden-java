package org.microraiden.conf;

import java.math.BigInteger;

public class Configuration {
    private BigInteger gasPrice;
    private boolean debugInfo;
    private String rpcAddress;
    private String channelAddr;
    private String tokenAddr;
    private String tokenABI;
    private String channelABI;
    private String appendingZerosForETH;
    private String appendingZerosForTKN;
    private int maxDepositBits;

    public BigInteger getGasPrice() {
        return gasPrice;
    }

    public void setGasPrice(BigInteger gasPrice) {
        this.gasPrice = gasPrice;
    }

    public boolean isDebugInfo() {
        return debugInfo;
    }

    public void setDebugInfo(boolean debugInfo) {
        this.debugInfo = debugInfo;
    }

    public String getRpcAddress() {
        return rpcAddress;
    }

    public void setRpcAddress(String rpcAddress) {
        this.rpcAddress = rpcAddress;
    }

    public String getChannelAddr() {
        return channelAddr;
    }

    public void setChannelAddr(String channelAddr) {
        this.channelAddr = channelAddr;
    }

    public String getTokenAddr() {
        return tokenAddr;
    }

    public void setTokenAddr(String tokenAddr) {
        this.tokenAddr = tokenAddr;
    }

    public String getTokenABI() {
        return tokenABI;
    }

    public void setTokenABI(String tokenABI) {
        this.tokenABI = tokenABI;
    }

    public String getChannelABI() {
        return channelABI;
    }

    public void setChannelABI(String channelABI) {
        this.channelABI = channelABI;
    }

    public String getAppendingZerosForETH() {
        return appendingZerosForETH;
    }

    public void setAppendingZerosForETH(String appendingZerosForETH) {
        this.appendingZerosForETH = appendingZerosForETH;
    }

    public String getAppendingZerosForTKN() {
        return appendingZerosForTKN;
    }

    public void setAppendingZerosForTKN(String appendingZerosForTKN) {
        this.appendingZerosForTKN = appendingZerosForTKN;
    }

    public int getMaxDepositBits() {
        return maxDepositBits;
    }

    public void setMaxDepositBits(int maxDepositBits) {
        this.maxDepositBits = maxDepositBits;
    }

    @Override
    public String toString() {
        return "Configuration{" +
                "gasPrice=" + gasPrice +
                ", debugInfo=" + debugInfo +
                ", rpcAddress='" + rpcAddress + '\'' +
                ", channelAddr='" + channelAddr + '\'' +
                ", tokenAddr='" + tokenAddr + '\'' +
                ", tokenABI='" + tokenABI + '\'' +
                ", channelABI='" + channelABI + '\'' +
                ", appendingZerosForETH='" + appendingZerosForETH + '\'' +
                ", appendingZerosForTKN='" + appendingZerosForTKN + '\'' +
                ", maxDepositBits=" + maxDepositBits +
                '}';
    }
}
