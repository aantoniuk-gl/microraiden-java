import java.math.BigInteger;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Signer {

    private static final byte[] RECEIVER_DATA_TYPE_NAME = "string message_idaddress receiveruint32 block_createduint192 balanceaddress contract".getBytes();
    private static final byte[] BALANCE_PROOF_SIGN = "Sender balance proof signature".getBytes();
    private static final byte[] SENDER_DATA_TYPE_NAME = "string message_idaddress senderuint32 block_createduint192 balanceaddress contract".getBytes();
    private static final byte[] CLOSING_SIGN = "Receiver closing signature".getBytes();

    private final String appendingZerosForTKN;
    private final Http http;
    private final boolean debugInfo;

    /**
     * Create a signer
     *
     * @param appendingZerosForTKN
     * @param http
     * @param debugInfo
     */
    public Signer(String appendingZerosForTKN, Http http, boolean debugInfo) {
        this.appendingZerosForTKN = appendingZerosForTKN;
        this.http = http;
        this.debugInfo = debugInfo;
    }

    /**
     * This function should be used by sender to create balance proof signature with receiver's address,
     * the block index where the channel has been created,
     * the balance that the sender would like to pay to the receiver, and the channel address
     *
     * @param senderWallet wallet of sender.
     * @param receiverAddr account ID of receiver in Hex String with 40 Hex digits, 0x is optional.
     * @param channelAddr  the channel address in Hex String with 40 Hex digits, 0x is optional.
     * @param openBlockNum the decimal literal of the open block index.
     * @param balance      the double literal of real amount of token paying to receiver
     * @return the balance proof signature.
     */
    public byte[] genBalanceMsgHashSig(Wallet senderWallet, String receiverAddr, String channelAddr, String openBlockNum, String balance) {
        return genMsgHashSig(senderWallet, receiverAddr, channelAddr, openBlockNum, balance, RECEIVER_DATA_TYPE_NAME, BALANCE_PROOF_SIGN);
    }

    /**
     * This function should be used by receiver to create channel closing signature with
     * a. sender's address,
     * b. the block index where the channel has been created,
     * c. the balance that the receiver would like to receive from sender, and
     * d. the channel address
     *
     * @param senderAddr   account ID of sender in Hex String with 40 Hex digits, 0x is optional.
     * @param channelAddr  the channel address in Hex String with 40 Hex digits, 0x is optional.
     * @param openBlockNum the decimal literal of the block index where the channel was open at.
     * @param balance      the double literal of real amount of token paying to receiver
     * @return the channel closing signature.
     */
    public byte[] genClosingMsgHashSig(Wallet receiverWallet, String senderAddr, String channelAddr, String openBlockNum, String balance) {
        return genMsgHashSig(receiverWallet, senderAddr, channelAddr, openBlockNum, balance, SENDER_DATA_TYPE_NAME, CLOSING_SIGN);
    }

    private byte[] genMsgHashSig(Wallet signerWallet,
            String targetAddr,
            String channelAddr,
            String openBlockNum,
            String balance,
            byte[] dataTypeName,
            byte[] signType) {
        try {
            signerWallet.update(http);
        } catch (Exception e) {
            return null;
        }
        byte[] closingMsgHash = genMsgHash(targetAddr, openBlockNum, balance, channelAddr, dataTypeName, signType);
        if (closingMsgHash == null) {
            System.out.println("Argument Error.");
            return null;
        }
        byte[] closingMsgHashHex;
        try {
            closingMsgHashHex = Hex.decodeHex(new String(Hex.encodeHex(closingMsgHash)).toCharArray());
        } catch (DecoderException e) {
            System.out.println("Couldn't convert msgHashHex = 0x" + Hex.encodeHexString(closingMsgHash) + " to byte array.");
            return null;
        }
        return signerWallet.signMessage(closingMsgHashHex);
    }

    private byte[] genMsgHash(
            String targetAddress,
            String open_block_number,
            String balance,
            String channelAddress,
            byte[] dataTypeName,
            byte[] signType) {
        byte[] receiverAddressBytes;
        byte[] channelAddressBytes;
        byte[] openBlockNumberBytes;
        byte[] balanceInChannelBytes;

        targetAddress = targetAddress.startsWith("0x") ? targetAddress.substring(2) : targetAddress;
        channelAddress = channelAddress.startsWith("0x") ? channelAddress.substring(2) : channelAddress;
        try {
            receiverAddressBytes = Hex.decodeHex(targetAddress.toCharArray());
        } catch (DecoderException e) {
            System.out.println("The provided receiver's address is not valid.");
            return null;
        }
        try {
            channelAddressBytes = Hex.decodeHex(channelAddress.toCharArray());
        } catch (DecoderException e) {
            System.out.println("The provided channel's address is not valid.");
            return null;
        }
        try {
            Integer.parseInt(open_block_number);
        } catch (NumberFormatException e) {
            System.out.println("The provided open block n is not valid.");
            return null;
        }

        BigInteger tempBalance;
        try {
            tempBalance = Utility.decimalToBigInteger(balance, appendingZerosForTKN);
        } catch (NumberFormatException e) {
            System.out.println("The provided balance is not valid.");
            return null;
        }

        try {
            openBlockNumberBytes = Hex.decodeHex(
                    Utility.prependingZeros(Integer.toHexString(Integer.parseInt(open_block_number)), 8).toCharArray());
            balanceInChannelBytes = Hex.decodeHex(
                    Utility.prependingZeros(tempBalance.toString(16), 48).toCharArray());
        } catch (DecoderException e) {
            System.out.println("The provided openBlockNumber is not valid.");
            return null;
        }
        byte[] dataValue = Utility.concatenateByteArrays(
                signType,
                receiverAddressBytes,
                openBlockNumberBytes,
                balanceInChannelBytes,
                channelAddressBytes);
        byte[] result = Utility.getSHA3HashHex(
                Utility.concatenateByteArrays(Utility.getSHA3HashHex(dataTypeName), Utility.getSHA3HashHex(dataValue)));
        if (debugInfo) {
            System.out.println("The value to be hashed in getBalanceMessageHash is " +
                    Hex.encodeHexString(Utility.concatenateByteArrays(Utility.getSHA3HashHex(dataTypeName), Utility.getSHA3HashHex(dataValue))));
            System.out.println("The result of getBalanceMessageHash is " + Hex.encodeHexString(result));
        }
        return result;
    }
}
