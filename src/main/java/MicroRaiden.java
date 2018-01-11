import java.lang.reflect.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.io.InputStream;
import java.io.IOException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.ethereum.core.CallTransaction;
import org.ethereum.core.Transaction;
import org.ethereum.core.CallTransaction.Contract;
import org.ethereum.crypto.ECKey;
import org.ethereum.util.ByteUtil;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.kocakosm.pitaya.security.Digest;
import org.kocakosm.pitaya.security.Digests;

/*
 * CLI for the MicroRaiden client
 */
public class MicroRaiden {
	private static final int LENGTH_OF_ID_IN_BYTES=20;
    private static final int INTERVAL_CHECK_TRANS_DONE=100;
	
	private static String rpcAddress=null;
	private static String channelAddr=null;
	private static String tokenAddr=null;
	private static String channelABI=null;
	private static String tokenABI=null;
	
	private static CallTransaction.Contract channelContract = null;
	private static CallTransaction.Contract tokenContract = null;
	private static String appendingZerosForETH=null;
    private static String appendingZerosForTKN=null;
    private static BigInteger MAX_DEPOSIT=null;
    private static BigInteger gasPrice=null;
    private static boolean debugInfo=false;

    
    private static Http httpAgent=null;

   	public MicroRaiden() {
        //should probably create an eth account with priv / pub keys
        //for doing the signing in the constructor
        
        //another option is we load the account based on what is
        //already saved in the folder
        
        //we need to think about what we should do if the sender / recv
        //are located in the same folder, or different folders and how
        //to store the files
    }
    
    /**
     * Create a new ethereum account to be used for testing microraiden
     * channels. Stores the account in the same folder where the
     * program is run. Note - there is no encryption on this private key
     * so it should be used for anything real!!
     * @param accountFile - the name of the output file for the account
     */
    public void createAccount(String accountFile) {
        ECKey keyPair = new ECKey();
        String address = new String(Hex.encodeHex(keyPair.getAddress()));
        System.out.println("Generated new account: 0x" + address);
        byte[] priv = keyPair.getPrivKeyBytes();
        
        try {
            OutputStream os = new FileOutputStream(accountFile + ".pkey");
            JSONObject obj=new JSONObject();
            obj.put("privkey", new String(Hex.encodeHex(priv)));
            obj.put("address", address);
            os.write(obj.toJSONString().getBytes());
            os.close();
        } catch (IOException e) {
            System.out.println("Couldn't write to file: " + accountFile + " " + e.toString());
        }
    }
    
    public void createAccountByPrivateKey(String accountFile, String privateKeyHex) {
    	if(privateKeyHex.startsWith("0x")) {
    		privateKeyHex=privateKeyHex.substring(2);
    	}
        ECKey keyPair = new ECKey();
        try{
        	keyPair=ECKey.fromPrivate(Hex.decodeHex(privateKeyHex.toCharArray()));
        }catch(DecoderException e) {
        	System.out.println("Couldn't create ECKey with privateKeyHex = " + privateKeyHex);
        }
        String address = new String(Hex.encodeHex(keyPair.getAddress()));
        System.out.println("Generated new account: 0x" + address);
        byte[] priv = keyPair.getPrivKeyBytes();
        
        try {
            OutputStream os = new FileOutputStream(accountFile + ".pkey");
            JSONObject obj=new JSONObject();
            obj.put("privkey", new String(Hex.encodeHex(priv)));
            obj.put("address", address);
            os.write(obj.toJSONString().getBytes());
            os.close();
        } catch (IOException e) {
            System.out.println("Couldn't write to file: " + accountFile + " " + e.toString());
        }
    }
    
//    public void loadAccountAndSignRecoverable(String accountName, String msgHashHex){
//    	if(msgHashHex.startsWith("0x")) {
//    		msgHashHex=msgHashHex.substring(2);
//    	}
//    	byte [] msgHashBytes=new byte[0];
//    	try {
//    		msgHashBytes=Hex.decodeHex(msgHashHex.toCharArray());
//    	}catch (DecoderException e) {
//        	System.out.println("Couldn't convert msgHashHex = " + msgHashHex + " to byte array.");
//        } 
//    	JSONParser parser = new JSONParser();
//    	ECKey keyPair = new ECKey();
//    	String privateKeyHex=new String();
//        try {     
//            Object obj = parser.parse(new FileReader(accountName+".pkey"));
//
//            JSONObject jsonObject =  (JSONObject) obj;
//
//            privateKeyHex = (String) jsonObject.get("privkey");
//            keyPair=ECKey.fromPrivate(Hex.decodeHex(privateKeyHex.toCharArray()));
//            
//        } catch (FileNotFoundException e) {
//        	System.out.println("Couldn't locate account file " + accountName + ".pkey");
//        } catch (ParseException e) {
//        	System.out.println("Couldn't parse contents in " + accountName + ".pkey as a JSON object.");
//        } catch (DecoderException e) {
//        	System.out.println("Couldn't create ECKey with privateKeyHex = " + privateKeyHex);
//        } catch (IOException e) {
//        	
//        }
//        String signature=keyPair.sign(msgHashBytes).toHex();
//        System.out.println("The signed recoverable signature is 0x" + signature + ".");
//    }

    /**
     * Reads all of the account files in the directory and lists which
     * are usable for testing channels with. Looks for files with the
     * .pkey extension.
     */
    public void listAccounts() {
        File dir = new File(".");
        File[] filesList = dir.listFiles();
        for (File file : filesList) {
            if (file.isFile()) {
                if(file.getName().contains(".pkey")) {
                    //System.out.println(file.getName());
                    try {
                        InputStream is = new FileInputStream(file.getName());
                        byte[] priv = IOUtils.toByteArray(is);
                        is.close();
                        ECKey keyPair = ECKey.fromPrivate(priv);
                        String address = new String(Hex.encodeHex(keyPair.getAddress()));
                        System.out.println("0x" + address);
                    } catch(IOException ex) {
                        System.out.println("Couldn't read from file: " + file.getName() + " " + ex.toString());
                    }
                }
            }
        }
    }
    private static byte[] getSHA3HashHex(byte[] messageToBeHashed) {
        Digest keccak256 = Digests.keccak256();
        keccak256.reset();
        keccak256.update(messageToBeHashed);
        return keccak256.digest();
    }

    private static byte[] getBalanceMsgHash(String receiverAddress,String open_block_number,String balance, String channelAddress) {
    	byte[] receiverAddressBytes=new byte[0];
    	byte[] channelAddressBytes=new byte[0];
    	byte[] openBlockNumberBytes=new byte[0];
    	byte[] balanceInChannelBytes=new byte[0];

    	receiverAddress=receiverAddress.startsWith("0x")?receiverAddress.substring(2):receiverAddress;
    	channelAddress=channelAddress.startsWith("0x")?channelAddress.substring(2):channelAddress;
    	try {
    		receiverAddressBytes=Hex.decodeHex(receiverAddress.toCharArray());
    	}catch(DecoderException e) {
    		System.out.println("The provided receiver's address is not valid.");
    		return null;
    	}
		if(receiverAddressBytes.length!=LENGTH_OF_ID_IN_BYTES) {
			System.out.println("The provided receiver's address is not valid.");
			return null;
		}
    	try {
    		channelAddressBytes=Hex.decodeHex(channelAddress.toCharArray());
    	}catch(DecoderException e) {
    		System.out.println("The provided channel's address is not valid.");
    		return null;
    	}
		if(channelAddressBytes.length!=LENGTH_OF_ID_IN_BYTES) {
			System.out.println("The provided channel's address is not valid.");
			return null;
		}
    	try {
    		Integer.parseInt(open_block_number);
    	}catch(NumberFormatException e){
    		System.out.println("The provided open block n is not valid.");
    		return null;
    	}
    	
    	BigInteger tempBalance=null;
    	try {
    		tempBalance=Utility.decimalToBigInteger(balance, appendingZerosForTKN);
    	}catch(NumberFormatException e) {
    		System.out.println("The provided balance is not valid.");
    		return null;
    	}
    	
    	try{
    		openBlockNumberBytes=Hex.decodeHex(Utility.prependingZeros(Integer.toHexString(Integer.parseInt(open_block_number)),8).toCharArray());
    		balanceInChannelBytes=Hex.decodeHex(Utility.prependingZeros(tempBalance.toString(16),48).toCharArray());
    	}catch(DecoderException e) {

    	}
    	byte[] dataTypeName="string message_idaddress receiveruint32 block_createduint192 balanceaddress contract".getBytes();
    	byte[] dataValue=Utility.concatenateByteArrays("Sender balance proof signature".getBytes(),receiverAddressBytes,openBlockNumberBytes,balanceInChannelBytes,channelAddressBytes);
    	byte[] result = getSHA3HashHex(Utility.concatenateByteArrays(getSHA3HashHex(dataTypeName),getSHA3HashHex(dataValue)));
    	if(debugInfo) {
    		System.out.println("The value to be hashed in getBalanceMessageHash is "+new String(Hex.encodeHexString(Utility.concatenateByteArrays(getSHA3HashHex(dataTypeName),getSHA3HashHex(dataValue)))));
    		System.out.println("The result of getBalanceMessageHash is "+new String(Hex.encodeHexString(result)));
    	}
    	return result;
    }
    
    private static byte[] getClosingMsgHash(String senderAddress,String open_block_number,String balance, String channelAddress) {
    	byte[] receiverAddressBytes=new byte[0];
    	byte[] channelAddressBytes=new byte[0];
    	byte[] openBlockNumberBytes=new byte[0];
    	byte[] balanceInChannelBytes=new byte[0];

    	senderAddress=senderAddress.startsWith("0x")?senderAddress.substring(2):senderAddress;
    	channelAddress=channelAddress.startsWith("0x")?channelAddress.substring(2):channelAddress;
    	try {
    		receiverAddressBytes=Hex.decodeHex(senderAddress.toCharArray());
    	}catch(DecoderException e) {
    		System.out.println("The provided receiver's address is not valid.");
    		return null;
    	}
		if(receiverAddressBytes.length!=LENGTH_OF_ID_IN_BYTES) {
			System.out.println("The provided receiver's address is not valid.");
			return null;
		}
    	try {
    		channelAddressBytes=Hex.decodeHex(channelAddress.toCharArray());
    	}catch(DecoderException e) {
    		System.out.println("The provided channel's address is not valid.");
    		return null;
    	}
		if(channelAddressBytes.length!=LENGTH_OF_ID_IN_BYTES) {
			System.out.println("The provided channel's address is not valid.");
			return null;
		}
    	try {
    		Integer.parseInt(open_block_number);
    	}catch(NumberFormatException e){
    		System.out.println("The provided open block n is not valid.");
    		return null;
    	}
    	
    	BigInteger tempBalance=null;
    	try {
    		tempBalance=Utility.decimalToBigInteger(balance, appendingZerosForTKN);
    	}catch(NumberFormatException e) {
    		System.out.println("The provided balance is not valid.");
    		return null;
    	}

    	
    	try{
    		openBlockNumberBytes=Hex.decodeHex(Utility.prependingZeros(Integer.toHexString(Integer.parseInt(open_block_number)),8).toCharArray());
    		balanceInChannelBytes=Hex.decodeHex(Utility.prependingZeros(tempBalance.toString(16),48).toCharArray());
    	}catch(DecoderException e) {

    	}
    	byte[] dataTypeName = "string message_idaddress senderuint32 block_createduint192 balanceaddress contract".getBytes();
    	byte[] dataValue= Utility.concatenateByteArrays("Receiver closing signature".getBytes(),receiverAddressBytes,openBlockNumberBytes,balanceInChannelBytes,channelAddressBytes);
    	byte[] result = getSHA3HashHex(Utility.concatenateByteArrays(getSHA3HashHex(dataTypeName),getSHA3HashHex(dataValue)));
    	if(debugInfo) {
    		System.out.println("The value to be hashed in getClosingMsgHash is "+new String(Hex.encodeHexString(Utility.concatenateByteArrays(getSHA3HashHex(dataTypeName),getSHA3HashHex(dataValue)))));
    		System.out.println("The result of getClosingMsgHash is "+new String(Hex.encodeHexString(result)));
    	}
    	return result;
    }
    private static byte[] getClosingMsgHashSig(String senderAddr,String channelAddr, String openBlockNum, String balance, String receiverName) {
    	Wallet receiverWallet=null;
    	try {
    		receiverWallet=new Wallet(receiverName);
    		receiverWallet.update(httpAgent);
    	}catch(Exception e) {
    		return null;
    	}
        byte [] closingMsgHash=getClosingMsgHash(senderAddr,openBlockNum,balance,channelAddr); 
        if(closingMsgHash==null) {
        	System.out.println("Argument Error.");
        	return null;
        }
        byte [] closingMsgHashHex=null;
    	try {
    		closingMsgHashHex=Hex.decodeHex(new String(Hex.encodeHex(closingMsgHash)).toCharArray());
    	}catch (DecoderException e) {
        	System.out.println("Couldn't convert msgHashHex = 0x" + Hex.encodeHexString(closingMsgHash) + " to byte array.");
        	return null;
    	}
        return receiverWallet.signMessage(closingMsgHashHex);
    	
    }
    private static byte[] getBalanceMsgHashSig(String receiverAddr,String channelAddr, String openBlockNum, String balance, String senderName) {
    	Wallet senderWallet=null;
    	try {
    		senderWallet=new Wallet(senderName);
    		senderWallet.update(httpAgent);
    	}catch(Exception e) {
    		return null;
    	}

        byte [] balanceMsgHash=getBalanceMsgHash(receiverAddr,openBlockNum,balance,channelAddr);
        if(balanceMsgHash==null) {
        	System.out.println("Argument Error.");
        	return null;
        }
        byte [] balanceMsgHashHex=null;
    	try {
    		balanceMsgHashHex=Hex.decodeHex(new String(Hex.encodeHex(balanceMsgHash)).toCharArray());
    	}catch (DecoderException e) {
        	System.out.println("Couldn't convert msgHashHex = 0x" + Hex.encodeHexString(balanceMsgHash) + " to byte array.");
        	return null;
    	}
        return senderWallet.signMessage(balanceMsgHashHex);
    }
	
    public void closeChannelCooperatively(String delegatorName, String senderName, String receiverName, String openBlockNum, String balance) {
    	BigInteger tempBalance=null;
    	try {
    		tempBalance=Utility.decimalToBigInteger(balance, appendingZerosForTKN);
    	}catch(NumberFormatException e) {
    		System.out.println("The provided balance is not valid.");
    		return;
    	}
    	Wallet delegatorWallet=null;
    	Wallet senderWallet=null;
    	Wallet receiverWallet=null;
    	try {
    		delegatorWallet=new Wallet(delegatorName);
    		delegatorWallet.update(httpAgent);
    		senderWallet=new Wallet(senderName);
    		senderWallet.update(httpAgent);
    		receiverWallet=new Wallet(receiverName);
    		receiverWallet.update(httpAgent);
    	}catch(Exception e) {
    		System.out.println("The delagator/sender/receiver cannot be found.");
    		return;
    	}
        
    	byte[] closing_Msg_Hash_Sig=getClosingMsgHashSig(senderWallet.getAccountID(),channelAddr,openBlockNum,balance,receiverName);
    	byte[] balance_Msg_Hash_Sig=getBalanceMsgHashSig(receiverWallet.getAccountID(),channelAddr,openBlockNum,balance,senderName);
    	if(closing_Msg_Hash_Sig==null||balance_Msg_Hash_Sig==null) {
    		System.out.println("Argument Error!");
    		return;
    	}
    	if(debugInfo) {
    		System.out.println("The signed closingMsgHash is 0x"+Hex.encodeHexString(closing_Msg_Hash_Sig));
    		System.out.println("The signed balanceMsgHash is 0x"+Hex.encodeHexString(balance_Msg_Hash_Sig));
    	}
     	byte[] balance_Msg_Hash_Sig_r=Arrays.copyOfRange(balance_Msg_Hash_Sig, 0, 32);
    	byte[] balance_Msg_Hash_Sig_s=Arrays.copyOfRange(balance_Msg_Hash_Sig, 32, 64);
    	byte[] balance_Msg_Hash_Sig_v=Arrays.copyOfRange(balance_Msg_Hash_Sig, 64, 65);
    	byte[] closing_Msg_Hash_Sig_r=Arrays.copyOfRange(closing_Msg_Hash_Sig, 0, 32);
    	byte[] closing_Msg_Hash_Sig_s=Arrays.copyOfRange(closing_Msg_Hash_Sig, 32, 64);
    	byte[] closing_Msg_Hash_Sig_v=Arrays.copyOfRange(closing_Msg_Hash_Sig, 64, 65);

    	//if(debugInfo) {
    		System.out.println("User "+delegatorName+" is the delegator to close the channel "+senderName+" ==> "+receiverName+" at balance = "+balance+".");
    	//}
       
    	
        CallTransaction.Function cooperativeClose=channelContract.getByName("cooperativeClose");
        byte [] cooperativeCloseFunctionBytes=cooperativeClose.encode(receiverWallet.getAccountID(),
        		new BigInteger(openBlockNum,10),tempBalance,balance_Msg_Hash_Sig_r,balance_Msg_Hash_Sig_s,new BigInteger(balance_Msg_Hash_Sig_v),closing_Msg_Hash_Sig_r,closing_Msg_Hash_Sig_s,new BigInteger(closing_Msg_Hash_Sig_v)); 
        String querycooperativeCloseGasString = "{\"method\":\"eth_estimateGas\"," +
                "\"params\":[" +
                "{" +
                "\"from\":\""+delegatorWallet.getAccountID()+"\"," +
                "\"to\":\""+channelAddr+"\"," +
                "\"value\":\""+"0x"+new BigInteger("0",10).toString(16)+"\","+
                "\"data\":\""+"0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(cooperativeCloseFunctionBytes))+"\"" +
                "}" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        if(debugInfo) {
        	System.out.println("The request string of querycooperativeCloseGasString is "+querycooperativeCloseGasString);
        }
        String cooperativeCloseGasEstimate="";
    	try {
    		cooperativeCloseGasEstimate=httpAgent.getHttpResponse(querycooperativeCloseGasString);
        }catch (IOException e) {
        	System.out.println("Invoking function with given arguments is not allowed.");
    		return;
        }
    	if(debugInfo) {
    		System.out.println("The estimatedGas of cooperative channel closing is "+cooperativeCloseGasEstimate+".");
    	}
    	
        Transaction cooperativeCloseTrans = new Transaction(Utility.bigIntegerToBytes(delegatorWallet.nonce()), // nonce
        		Utility.bigIntegerToBytes(gasPrice), // gas price
        		Utility.bigIntegerToBytes(new BigInteger(cooperativeCloseGasEstimate.substring(2),16)), // gas limit
                ByteUtil.hexStringToBytes(channelAddr), // to id
                Utility.bigIntegerToBytes(new BigInteger("0",10)), // value
                cooperativeCloseFunctionBytes, 42);// chainid
        delegatorWallet.signTransaction(cooperativeCloseTrans);
        String signedCooperativeCloseTranss = "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(cooperativeCloseTrans.getEncoded()));
        String cooperativeCloseSendRawTransactionString = "{\"method\":\"eth_sendRawTransaction\",\"params\":[\""
                + signedCooperativeCloseTranss + "\"],\"id\":42,\"jsonrpc\":\"2.0\"}";
        
    	String myTransactionID="";
    	try {
    		myTransactionID=httpAgent.getHttpResponse(cooperativeCloseSendRawTransactionString);
        }catch (IOException e) {
        	System.out.println("Fail to execute HTTP request.");
    		return;
        }
    	
        if(!"".equals(myTransactionID)) {
        	System.out.println("Waiting for Kovan to mine transactions ... ");
        	waitingForTransaction(myTransactionID);
        }
        //if(debugInfo) {
        	System.out.println("\bChannel has been closed.");  	
        //}
        
    	
    }
    /**
     * Lists the balances for a particular account and any balance
     * in the channel with the given remote peer
     */
    public void listBalances(String account, String remotePeer) {
        
    }
    
    public void getTokenBalance(String accountName){
    	Wallet myWallet=null;
    	try{
    		myWallet=new Wallet(accountName);
    		myWallet.update(httpAgent);
    	}catch(Exception e) {
    		System.out.println("The wallet cannot be retrived for "+accountName);
    		return;
    	}
        
        CallTransaction.Function balanceOf = tokenContract.getByName("balanceOf");
        byte [] functionBytes=balanceOf.encode(myWallet.getAccountID());
        String requestString = "{\"method\":\"eth_call\"," +
                "\"params\":[" +
                "{" +
                "\"to\":\""+tokenAddr+"\"," +
                "\"data\":\""+"0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(functionBytes))+"\"" +
                "}," +
                "\"latest\"" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        if(debugInfo) {
        	System.out.println("Request in getTokenBalance = "+requestString);
        }
        String myTokenBalance="";
        try {
        	myTokenBalance=httpAgent.getHttpResponse(requestString);
        }catch (IOException e) {
        	System.out.println("Cannot get token balance for "+accountName);
    		return;
        }
    	System.out.println("Balance of "+accountName+" = "+new Float(new BigInteger(myTokenBalance.substring(2),16).floatValue()/(new BigInteger(appendingZerosForTKN,10).floatValue())).toString()+" TKN");
    	
    }
   
    
    public void createChannel(String senderAccountName, String receiverAccountName, String deposit) {
    	BigInteger initDeposit=null;
    	try {
    		initDeposit=Utility.decimalToBigInteger(deposit, appendingZerosForTKN);
    	}catch(NumberFormatException e) {
    		System.out.println("The provided balance is not valid.");
    		return;
    	}	    	
    	if(MAX_DEPOSIT.compareTo(initDeposit)<0) {
    		System.out.println("Please choose a deposit <= "+MAX_DEPOSIT.toString(10));
    		return;
    	}
    	Wallet senderWallet=null;
    	Wallet receiverWallet=null;
    	try {
    		senderWallet=new Wallet(senderAccountName);
    		senderWallet.update(httpAgent);
    		receiverWallet=new Wallet(receiverAccountName);
    		receiverWallet.update(httpAgent);
    	}catch(Exception e) {
    		System.out.println("The sender/receiver cannot be found.");
    		return;
    	}

        
    	//if(debugInfo) {
    		System.out.println("User "+senderAccountName+" tries to open a channel to pay "+receiverAccountName+" up to " + deposit +" Tokens at maximum.");
    	//}
        
        CallTransaction.Function approve=tokenContract.getByName("approve");
        byte [] approveFunctionBytes=approve.encode(channelAddr,initDeposit); 
        String queryApproveGasString = "{\"method\":\"eth_estimateGas\"," +
                "\"params\":[" +
                "{" +
                "\"from\":\""+senderWallet.getAccountID()+"\"," +
                "\"to\":\""+tokenAddr+"\"," +
                "\"value\":\""+"0x"+new BigInteger("0",10).toString(16)+"\","+
                "\"data\":\""+"0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(approveFunctionBytes))+"\"" +
                "}" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        if(debugInfo) {
        	System.out.println("The request string of queryApproveGasString is "+queryApproveGasString);
        }
        String approveGasEstimate="";
    	try {
    		approveGasEstimate=httpAgent.getHttpResponse(queryApproveGasString);
        }catch (IOException e) {
        	System.out.println("Invoking function with given arguments is not allowed.");
    		return;
        }
    	if(debugInfo) {
    		System.out.println("The estimatedGas of approve is "+approveGasEstimate+".");
    		System.out.println("The nonce of "+senderAccountName+" is "+senderWallet.nonce().toString(10));
    	}
    	
        Transaction approveTrans = new Transaction(Utility.bigIntegerToBytes(senderWallet.nonce()), // nonce
        		Utility.bigIntegerToBytes(gasPrice), // gas price
        		Utility.bigIntegerToBytes(new BigInteger(approveGasEstimate.substring(2),16)), // gas limit
                ByteUtil.hexStringToBytes(tokenAddr), // to id
                Utility.bigIntegerToBytes(new BigInteger("0",10)), // value
                approveFunctionBytes, 42);// chainid
        senderWallet.signTransaction(approveTrans);
        String signedApproveTrans = "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(approveTrans.getEncoded()));
        String approveSendRawTransactionString = "{\"method\":\"eth_sendRawTransaction\",\"params\":[\""
                + signedApproveTrans + "\"],\"id\":42,\"jsonrpc\":\"2.0\"}";
        
    	String myTransactionID1="";
    	try {
    		myTransactionID1=httpAgent.getHttpResponse(approveSendRawTransactionString);
        }catch (IOException e) {
        	System.out.println("Fail to execute HTTP request.");
    		return;
        }
    	
        if(!"".equals(myTransactionID1)) {
        	System.out.println("Waiting for Kovan to mine transactions ... ");
        	waitingForTransaction(myTransactionID1);
        }
        if(debugInfo) {
        	System.out.println("\bApproving funding transfer is done.");  	
        }
        try {
        	senderWallet.updateNonce(httpAgent);
        }catch(Exception e){
        	System.out.println("Updating nonce value is failed.");
        	return;
        }
        if(debugInfo) {
        	System.out.println("The nonce of "+senderAccountName+" is "+senderWallet.nonce().toString(10));
        }

    	CallTransaction.Function createChannelERC20 = channelContract.getByName("createChannelERC20");
        byte [] createChannelERC20FunctionBytes=createChannelERC20.encode(receiverWallet.getAccountID(),initDeposit);        
        String queryCreatChannelGasString = "{\"method\":\"eth_estimateGas\"," +
                "\"params\":[" +
                "{" +
                "\"from\":\""+senderWallet.getAccountID()+"\"," +
                "\"to\":\""+channelAddr+"\"," +
                "\"value\":\""+"0x"+new BigInteger("0",10).toString(16)+"\","+
                "\"data\":\""+"0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(createChannelERC20FunctionBytes))+"\"" +
                "}" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        if(debugInfo) {
        	System.out.println("The request string of queryCreatChannelGasString is "+queryCreatChannelGasString);
        }
        String creatChannelGasEstimate="";
    	try {
    		creatChannelGasEstimate=httpAgent.getHttpResponse(queryCreatChannelGasString);
        }catch (IOException e) {
        	System.out.println("Invoking function with given arguments is not allowed.");
    		return;
        }

    	if(debugInfo) {
    		System.out.println("The estimatedGas of createChannelERC20 is "+creatChannelGasEstimate);
    	}
        Transaction createTrans = new Transaction(Utility.bigIntegerToBytes(senderWallet.nonce()), // nonce
        		Utility.bigIntegerToBytes(gasPrice), // gas price
        		Utility.bigIntegerToBytes(new BigInteger(creatChannelGasEstimate.substring(2),16)), // gas limit
                ByteUtil.hexStringToBytes(channelAddr), // to id
                Utility.bigIntegerToBytes(new BigInteger("0",10)), // value
                createChannelERC20FunctionBytes, 42);// chainid
        senderWallet.signTransaction(createTrans);
        String signedChannelCreationTrans = "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(createTrans.getEncoded()));
        String createChannelSendRawTransactionString = "{\"method\":\"eth_sendRawTransaction\",\"params\":[\""
                + signedChannelCreationTrans + "\"],\"id\":42,\"jsonrpc\":\"2.0\"}";
        
    	String myTransactionID2="";
    	try {
    		myTransactionID2=httpAgent.getHttpResponse(createChannelSendRawTransactionString);
        }catch (IOException e) {
        	System.out.println("Fail to execute HTTP request.");
    		return;
        }
    	
        if(!"".equals(myTransactionID2)) {
	        String blockNumberHex=waitingForTransaction(myTransactionID2);

	        System.out.println("\bChannel has been opened in block "+new BigInteger(blockNumberHex.substring(2),16).toString(10));
	        
	        Digest keccak256 = Digests.keccak256();

	        
	        String firstArgVal=senderWallet.getAccountID().substring(2).toLowerCase();
	        String secondArgVal=receiverWallet.getAccountID().substring(2).toLowerCase();
	        String thirdArgVal=Utility.prependingZeros(blockNumberHex.substring(2), 8);
	        try{
	        	byte[] data = Utility.concatenateByteArrays(Hex.decodeHex(firstArgVal.toCharArray()),Hex.decodeHex(secondArgVal.toCharArray()),Hex.decodeHex(thirdArgVal.toCharArray()));
	        	if(debugInfo) {
	        		System.out.println("The keccak256 argument of bytes in string "+Hex.encodeHexString(data));	
	        	}
	        	byte[] keyInBytes=keccak256.reset().update(data).digest();
	        	String channelKeyHex = "0x"+new String(Hex.encodeHexString(keyInBytes));
	        	System.out.println("\bChannel key = "+channelKeyHex);
	        	System.out.println("Channel on Koven can be found on page:\nhttps://kovan.etherscan.io/address/"+channelAddr+"#readContract");
	        }catch (DecoderException e) {
	        	System.out.println("Hex string cannot be converted to byte array!");
	        }        
	        
        }
    	return;

    }
    
    public void buyToken(String accountName,String amountOfEther){
    	BigInteger value=null;
    	try {
    		value=Utility.decimalToBigInteger(amountOfEther, appendingZerosForETH);
    	}catch(NumberFormatException e) {
    		System.out.println("The provided balance is not valid.");
    		return;
    	}	
    	
    	Wallet myWallet=null;
    	try{
    		myWallet=new Wallet(accountName);
    		myWallet.update(httpAgent);
    	}catch(Exception e) {
    		System.out.println("Cannot retrive the wallet for "+accountName);
    		return;
    	}
    	
    	if(debugInfo) {
    		System.out.println("User "+accountName+"("+myWallet.getAccountID()+") will trade "+value.toString()+" Wei to Token.");
    	}
        
        CallTransaction.Function mint = tokenContract.getByName("mint");
        byte [] functionBytes=mint.encode();
        String queryGasString = "{\"method\":\"eth_estimateGas\"," +
                "\"params\":[" +
                "{" +
                "\"from\":\""+myWallet.getAccountID()+"\"," +
                "\"to\":\""+tokenAddr+"\"," +
                "\"value\":\""+"0x"+value.toString(16)+"\","+
                "\"data\":\""+"0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(functionBytes))+"\"" +
                "}" +
                "]," +
                "\"id\":42,\"jsonrpc\":\"2.0\"}";
        String gasEstimateResult="";
    	try {
    		gasEstimateResult=httpAgent.getHttpResponse(queryGasString);
        }catch (IOException e) {
        	System.out.println("Invoking function with given arguments is not allowed.");
    		return;
        }
    	if(debugInfo) {
    		System.out.println("The estimatedGas of mint is "+gasEstimateResult);
    	}
    	
    	if(debugInfo) {
    		System.out.println("Total ether balance of "+accountName+" is "+myWallet.etherBalance().toString(10));
    	}
    	if(new BigInteger(gasEstimateResult.substring(2),16).multiply(gasPrice).add(value).compareTo(myWallet.etherBalance())>0) {
    		System.out.println("Insufficient Ether to finish the transaction.");
    		return;
    	}
    	
    
    	if(debugInfo) {
    		System.out.println("The nonce of "+accountName+" is "+myWallet.nonce());
    	}
    	
        Transaction t = new Transaction(Utility.bigIntegerToBytes(myWallet.nonce()), // nonce
        		Utility.bigIntegerToBytes(gasPrice), // gas price
        		Utility.bigIntegerToBytes(new BigInteger(gasEstimateResult.substring(2),16)), // gas limit
                ByteUtil.hexStringToBytes(tokenAddr), // to id
                Utility.bigIntegerToBytes(value), // value
                functionBytes, 42);// chainid
        myWallet.signTransaction(t);
        String signedTrans = "0x" + new String(org.apache.commons.codec.binary.Hex.encodeHex(t.getEncoded()));
        String mintSendRawTransactionString = "{\"method\":\"eth_sendRawTransaction\",\"params\":[\""
                + signedTrans + "\"],\"id\":42,\"jsonrpc\":\"2.0\"}";
        
    	String myTransactionID="";
    	try {
    		myTransactionID=httpAgent.getHttpResponse(mintSendRawTransactionString);
        }catch (IOException e) {
        	System.out.println("Fail to execute HTTP request.");
    		return;
        }
    	
        if(!"".equals(myTransactionID)) {
        	waitingForTransaction(myTransactionID);
        }
        System.out.println("\bYou have been given 50 tokens.");

    	
    }
    
    private static String waitingForTransaction(String myTransactionID) {
    	if(debugInfo) {
    		System.out.println("Transaction ID = "+myTransactionID);
    	}
		boolean loop=true;
		String blockNumber=new String();
        while(loop){
        	Object tempObj=null;
        	try {
                CloseableHttpClient httpClient = HttpClientBuilder.create().build();
                HttpPost request = new HttpPost(rpcAddress);     
                request.addHeader("content-type", "application/json");
                String queryTransactionString = "{\"method\":\"eth_getTransactionReceipt\"," +
                        "\"params\":[\"" +
                        myTransactionID +
                        "\"]," +
                        "\"id\":42,\"jsonrpc\":\"2.0\"}";
                StringEntity params = new StringEntity(queryTransactionString);
                request.setEntity(params);
                CloseableHttpResponse response = httpClient.execute(request);
                String temp =new BasicResponseHandler().handleResponse(response);
                response.close();
                httpClient.close();
              
                JSONParser parser = new JSONParser();
                JSONObject jobj=(JSONObject)parser.parse(temp);
                for (Object key : jobj.keySet()) {
                    if (((String)key).equalsIgnoreCase("result")) {
                    	tempObj=jobj.get(key);
                    }
                }
            }catch (UnsupportedEncodingException e) {
            	System.out.println("UnsupportedEncodingException: "+e);
            }catch (ClientProtocolException e) {
            	System.out.println("ClientProtocolException: "+e);
            }catch (IOException e) {
            	System.out.println("IOException: "+e);
            }catch(ParseException e) {
            	System.out.println("ParseException: "+e);
            }catch (NumberFormatException e){
            	System.out.println("NumberFormatException="+e);
            }
            if(tempObj==null){
                //do nothing
            }else{
            	loop=false;
                JSONObject jsonObject=(JSONObject) tempObj;
                //The jsonObject can be further parsed to get more information.
                blockNumber = (String)jsonObject.get("blockNumber");
            }
            try {
                Thread.sleep(INTERVAL_CHECK_TRANS_DONE);
                System.out.print("\b\\");
                Thread.sleep(INTERVAL_CHECK_TRANS_DONE);
                System.out.print("\b|");
                Thread.sleep(INTERVAL_CHECK_TRANS_DONE);
                System.out.print("\b/");
                Thread.sleep(INTERVAL_CHECK_TRANS_DONE);
                System.out.print("\b-");

            }catch (InterruptedException e) {
            	
            }
        }
        return blockNumber;
	}
    
    public void getAccountInfo(String accountName) {
    	Wallet myWallet=null;
    	try {
    		myWallet=new Wallet(accountName);
        	myWallet.update(httpAgent);
    	}catch(Exception e) {
    		System.out.println("Cannot retrive for "+accountName);
    		return;
    	}
    	System.out.println("**********************************************");
    	System.out.println("AccountName:\t"+myWallet.accountName());
    	System.out.println("AccountID:\t"+myWallet.getAccountID());
    	System.out.println("AccountNonce:\t"+myWallet.nonce().toString(10));
    	System.out.println("AccountBalance:\t"+myWallet.etherBalance().toString(10));
    	System.out.println("**********************************************");
    }
    public void getEtherBalance(String accountName){
    	JSONParser parser = new JSONParser();
    	JSONObject jobj=new JSONObject();
        try {     
        	jobj = (JSONObject)parser.parse(new FileReader(accountName+".pkey"));
            
        } catch (FileNotFoundException e) {
        	System.out.println("Couldn't locate account file " + accountName + ".pkey");
        	return;
        } catch (ParseException e) {
        	System.out.println("Couldn't parse contents in " + accountName + ".pkey as a JSON object.");
        	return;
        } catch (IOException e) {
        	System.out.println("Couldn't parse contents in " + accountName + ".pkey as a JSON object.");
        	return;
        }
        
        String address = "0x"+(String) jobj.get("address");

        String requestString="{\"method\":\"eth_getBalance\",\"params\":[\""+address+"\"],\"id\":42,\"jsonrpc\":\"2.0\"}";
        //System.out.println("The request string in getEtherBalance is "+requestString);
        String myEtherBalance="";
    	try {
    		myEtherBalance=httpAgent.getHttpResponse(requestString);
        }catch (IOException e) {
        	System.out.println("Invoking function with given arguments is not allowed.");
    		return;
        }
    	System.out.println("Ether Balance of "+accountName+"("+address+")"+" is "+new Float(new BigInteger(myEtherBalance.substring(2),16).floatValue()/(new BigInteger(appendingZerosForETH,10).floatValue())).toString()+" Ether");
    	
    }
    
    /**
     * Displays a list of all available functions
     */
    private static void displayFunctions() {
        System.out.println("Possible Functions: ");
        Class cls = MicroRaiden.class;
        Method methlist[] = cls.getDeclaredMethods();
        for (int i = 0; i < methlist.length; i++) {
            Method m = methlist[i];
            if(m.getName().equals("main") 
            		|| m.getName().equals("displayFunctions")
            		|| m.getName().equals("getECKeyByName")
            		|| m.getName().equals("waitingForTransaction")
            		|| m.getName().equals("getBalanceMsgHashSig")
            		|| m.getName().equals("getClosingMsgHashSig")
            		|| m.getName().equals("getClosingMsgHash")
            		|| m.getName().equals("getBalanceMsgHash")) {
                continue;
            }
            
            String params = "";
            Class pvec[] = m.getParameterTypes();
            for (int j = 0; j < pvec.length; j++) {
                params = params + pvec[j];
                if(j < (pvec.length - 1)) {
                    params = params + ", ";
                }
            }
            
            System.out.println("  " + m.getReturnType() + " " + m.getName() + "(" + params + ")");
        }
    }
    
    public static void main(String[] args) throws Exception {
    	
        MicroRaiden mr = new MicroRaiden();
        JSONParser parser = new JSONParser();
        
        try {     
            Object obj = parser.parse(new FileReader("rm-ethereum.conf"));

            JSONObject jsonObject =  (JSONObject) obj;
            for (Object key : jsonObject.keySet()) {
            	switch((String)key) {
            		case "debugInfo":
            			debugInfo=((String) jsonObject.get(key)).equals("true")?true:false;
            			break;
            		case "gasPrice":
            			gasPrice=new BigInteger((String) jsonObject.get(key),10);
                        if(debugInfo) {
                        	System.out.println("The global gas price is set to be "+gasPrice.toString(10));
                        }
            			break;
            		case "rpcAddress":
            			rpcAddress=((String) jsonObject.get(key));
                        if(debugInfo) {
                        	System.out.println("rpcAddress = "+rpcAddress);
                        }
            			break;
            		case "channelAddr":
            			channelAddr=((String) jsonObject.get(key));
                        if(debugInfo) {
                        	System.out.println("channelAddr = "+channelAddr);
                        }
            			break;
            		case "tokenAddr":
            			tokenAddr=((String) jsonObject.get(key));
                        if(debugInfo) {
                        	System.out.println("tokenAddr = "+tokenAddr);
                        }
            			break;
            		case "channelABI":
            			channelABI=((String) jsonObject.get(key));
                        if(debugInfo) {
                        	System.out.println("channelABI = "+channelABI);
                        }
                        channelContract = new CallTransaction.Contract(channelABI);
            			break;
            		case "tokenABI":
            			tokenABI=((String) jsonObject.get(key));
                        if(debugInfo) {
                        	System.out.println("tokenABI = "+tokenABI);
                        }
                        tokenContract = new CallTransaction.Contract(tokenABI);
            			break;
            		case "appendingZerosForETH":
            			appendingZerosForETH=((String) jsonObject.get(key));
                        if(debugInfo) {
                        	System.out.println("appendingZerosForETH = "+appendingZerosForETH);
                        }
            			break;
            		case "appendingZerosForTKN":
            			appendingZerosForTKN=((String) jsonObject.get(key));
                        if(debugInfo) {
                        	System.out.println("appendingZerosForTKN = "+appendingZerosForTKN);
                        }
            			break;
            		case "maxDepositBits":
            			MAX_DEPOSIT=new BigInteger("2",10).pow(Integer.parseInt(((String) jsonObject.get(key))));
            			gasPrice=new BigInteger((String) jsonObject.get(key),10);
                        if(debugInfo) {
                        	System.out.println("MAX_DEPOSIT ="+MAX_DEPOSIT.toString(16));
                        }
            			break;

            			
            		default:
            			System.out.println("Unknown key is detected when parsing the configuration files.");
            	}
            	httpAgent=new Http(rpcAddress,debugInfo);
                
            }
            
        } catch (FileNotFoundException e) {
        	
        } catch (ParseException e) {
        	System.out.println("Couldn't parse contents in m-ethereum.conf as a JSON object."+e);
        } catch (IOException e) {
        	System.out.println("Couldn't parse contents in m-ethereum.conf as a JSON object."+e);
        }
        
        if(args.length < 1) {
            System.out.println("Usage: microraiden-java <function> <args>");
            displayFunctions();
            return;
        }
        
        //get the function name - use reflection to call
        String functionName = args[0];
        
        //some trickery to get the method with the params (if we just
        //try to search for the method without the params specified it
        //will only look for parameter-less version
        Class cls = Class.forName("MicroRaiden");
        Method method = null; 
        Method methlist[] = cls.getDeclaredMethods();
        for (int i = 0; i < methlist.length; i++) {
            Method m = methlist[i];
            if(m.getName().equals(functionName)) {
                method = m;
                break;
            }
        }
        
        //cast the args to the correct type for the function params
        //note if you use a weird type this will probably shit itself.
        Object arglist[] = new Object[args.length - 1];
        Class pvec[] = method.getParameterTypes();
        for(int i = 1; i < args.length; i++) {
            if(pvec.length < i) {
                break;
            }
            
            String argtype = args[i].getClass().getName();
            String actualType = pvec[i-1].getName();
            if(!argtype.equals(actualType)) {
                switch(actualType) {
                    case "int": {
                        arglist[i-1] = Integer.parseInt(args[i]);
                        break;
                    }
                    default: {
                        System.out.println("UNKNOWN PARAM TYPE: " + actualType);
                        return;
                    }
                }
            } else {
                arglist[i-1] = args[i];
            }
        }
        
        Object retobj = method.invoke(mr, arglist);
    }    
}
