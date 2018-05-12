import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.ethereum.core.CallTransaction;
import org.ethereum.crypto.ECKey;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/*
 * CLI for the MicroRaiden client
 */
public class MicroRaiden {

    private static String rpcAddress = null;
    private static String channelAddr = null;
    private static String tokenAddr = null;
    private static CallTransaction.Contract tokenContract = null;

    private static CallTransaction.Contract channelContract = null;
    private static BigInteger MAX_DEPOSIT = null;
    private static String appendingZerosForTKN = null;
    private static String appendingZerosForETH = null;
    private static BigInteger gasPrice = null;
    private static boolean debugInfo = false;

    private static Http httpAgent = null;
    private static Token token = null;
    private static TransferChannel transferChannel = null;

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
     * Create a new Ethereum account to be used for testing microraiden
     * channels. Stores the account in the same folder where the
     * program is run. Note - there is no encryption on this private key
     * so it should be used for anything real!!
     *
     * @param accountFile - the name of the output file for the account
     */
    public void createAccount(String accountFile) {
        ECKey keyPair = new ECKey();
        String address = new String(Hex.encodeHex(keyPair.getAddress()));
        System.out.println("Generated new account: 0x" + address);
        byte[] priv = keyPair.getPrivKeyBytes();

        try {
            OutputStream os = new FileOutputStream(accountFile + ".pkey");
            JSONObject obj = new JSONObject();
            obj.put("privkey", new String(Hex.encodeHex(priv)));
            obj.put("address", address);
            os.write(obj.toJSONString().getBytes());
            os.close();
        } catch (IOException e) {
            System.out.println("Couldn't write to file: " + accountFile + " " + e.toString());
        }
    }

    /**
     * This function is another way to create the account file for testing purpose.
     * After the user creates an account with, for example, MetaMask, the privateKey
     * can be found and used here to create the account file to perform tests on test nets.
     *
     * @param accountFile   the name of the account to be created.
     * @param privateKeyHex the privateKey given in 64 Hex digits. "0x" prefix is optional.
     */
    public void createAccountByPrivateKey(String accountFile, String privateKeyHex) {
        privateKeyHex = privateKeyHex.startsWith("0x") ? privateKeyHex.substring(2) : privateKeyHex;
        if (privateKeyHex.length() != 64) {
            System.out.println("The private key should be given in 64 HEX numbers.");
            return;
        }
        ECKey keyPair = new ECKey();
        try {
            keyPair = ECKey.fromPrivate(Hex.decodeHex(privateKeyHex.toCharArray()));
        } catch (DecoderException e) {
            System.out.println("Couldn't create ECKey with privateKeyHex = " + privateKeyHex);
        }
        String address = new String(Hex.encodeHex(keyPair.getAddress()));
        System.out.println("Generated new account: 0x" + address);
        byte[] priv = keyPair.getPrivKeyBytes();
        try {
            OutputStream os = new FileOutputStream(accountFile + ".pkey");
            JSONObject obj = new JSONObject();
            obj.put("privkey", new String(Hex.encodeHex(priv)));
            obj.put("address", address);
            os.write(obj.toJSONString().getBytes());
            os.close();
        } catch (IOException e) {
            System.out.println("Couldn't write to file: " + accountFile + " " + e.toString());
        }
    }

    /**
     * Reads all of the account files in the directory and lists which
     * are usable for testing channels with. Looks for files with the
     * .pkey extension.
     */
    public void listAccounts() {
        JSONParser parser = new JSONParser();
        JSONObject jobj = new JSONObject();
        File dir = new File(".");
        File[] filesList = dir.listFiles();
        for (File file : filesList) {
            if (file.isFile()) {
                if (file.getName().contains(".pkey")) {
                    //System.out.println(file.getName());
                    try {
                        jobj = (JSONObject) parser.parse(new FileReader(file.getName()));
                        System.out.println("0x" + ((String) jobj.get("address")));
                    } catch (Exception ex) {
                        System.out.println("Couldn't read from file: " + file.getName() + " " + ex.toString());
                    }
                }
            }
        }
    }

    /**
     * @param accountName the name of the account would like to query.
     */
    public void getAccountInfo(String accountName) {
        Wallet myWallet;
        try {
            byte[] myPrivateKey = getPrivateKeyByName(accountName);
            myWallet = new Wallet(myPrivateKey);
            myWallet.update(httpAgent);
        } catch (Exception e) {
            System.out.println("Cannot retrive for " + accountName);
            return;
        }
        System.out.println("**********************************************");
        System.out.println("AccountName:\t" + accountName);
        System.out.println("AccountID:\t" + myWallet.getAccountID());
        System.out.println("AccountNonce:\t" + myWallet.nonce().toString(10));
        System.out.println("AccountBalance:\t" + myWallet.etherBalance().toString(10) + " (Wei)");
        System.out.println("**********************************************");
    }

    /**
     * Allows user buy some token. If the user has no token, he can only put zero deposit when creating the channel.
     *
     * @param accountName   the name of the buyer
     * @param amountOfEther the double literal of Ethers would like to trade for tokens. 0.1 Ether OK for demo.
     */
    public void buyToken(String accountName, String amountOfEther) {
        Wallet myWallet;
        try {
            byte[] myPrivateKey = getPrivateKeyByName(accountName);
            myWallet = new Wallet(myPrivateKey);
            myWallet.update(httpAgent);
        } catch (Exception e) {
            System.out.println("Cannot retrive the wallet for " + accountName);
            return;
        }

        token.mint(myWallet, amountOfEther);
    }

    public void getTokenBalance(String accountName) {
        Wallet myWallet;
        try {
            byte[] myPrivateKey = getPrivateKeyByName(accountName);
            myWallet = new Wallet(myPrivateKey);
            myWallet.update(httpAgent);
        } catch (Exception e) {
            System.out.println("The wallet cannot be retrived for " + accountName);
            return;
        }

        token.balanceOf(myWallet.getAccountID());
    }

    /**
     * Create a channel from sender to receiver. The sender needs to sign the transactions of approve and channel creation
     *
     * @param senderAccountName   the name of the sender
     * @param receiverAccountName the name of the receiver
     * @param deposit             the double literal as the initial deposit of the channel.
     */
    public void createChannel(String senderAccountName, String receiverAccountName, String deposit) {
        Wallet senderWallet;
        Wallet receiverWallet;
        try {
            byte[] senderPrivateKey = getPrivateKeyByName(senderAccountName);
            senderWallet = new Wallet(senderPrivateKey);

            byte[] receiverPrivateKey = getPrivateKeyByName(receiverAccountName);
            receiverWallet = new Wallet(receiverPrivateKey);
        } catch (Exception e) {
            System.out.println("The sender/receiver cannot be found.");
            return;
        }

        transferChannel.createChannel(senderWallet, receiverWallet.getAccountID(), deposit);
    }

    /**
     * This function is to close the channel in a cooperative manner.
     *
     * @param delegatorName the delegator's name used to retrieve the wallet, as the signer of the channel closing transaction.
     * @param senderName    the name of sender of this channel
     * @param receiverName  the name of receiver of this channel
     * @param openBlockNum  the block index where the channel was open in decimal literal
     * @param balance       the double literal of the amount of taken paying to the receiver.
     */
    public void closeChannelCooperatively(String delegatorName, String senderName, String receiverName, String openBlockNum, String balance) {
        Wallet delegatorWallet;
        Wallet senderWallet;
        Wallet receiverWallet;
        try {
            byte[] delegatorPrivateKey = getPrivateKeyByName(delegatorName);
            delegatorWallet = new Wallet(delegatorPrivateKey);

            byte[] senderPrivateKey = getPrivateKeyByName(senderName);
            senderWallet = new Wallet(senderPrivateKey);

            byte[] receiverPrivateKey = getPrivateKeyByName(receiverName);
            receiverWallet = new Wallet(receiverPrivateKey);
        } catch (Exception e) {
            System.out.println("The delagator/sender/receiver cannot be found.");
            return;
        }

        System.out.println("User " + delegatorWallet.getAccountID() + " is the delegator to close the channel " +
                senderName + " ==> " + receiverName + " at balance = " + balance + ".");

        MessageSigner messageSigner = new MessageSigner(appendingZerosForTKN, httpAgent, debugInfo);
        byte[] balanceMsgHashSig = messageSigner.genBalanceMsgHashSig(senderWallet, receiverWallet.getAccountID(), channelAddr, openBlockNum, balance);
        byte[] closingMsgHashSig = messageSigner.genClosingMsgHashSig(receiverWallet, senderWallet.getAccountID(), channelAddr, openBlockNum, balance);

        transferChannel.closeChannelCooperatively(
                delegatorWallet,
                receiverWallet.getAccountID(),
                balanceMsgHashSig,
                closingMsgHashSig,
                openBlockNum,
                balance);
    }

    /**
     * Retrieve private key from file by account name.
     *
     * @param accountName name of the account used to get the wallet
     * @return byte array of private key
     * @throws DecoderException
     * @throws ParseException
     * @throws IOException
     */
    private byte[] getPrivateKeyByName(String accountName) throws DecoderException, ParseException, IOException {
        JSONParser parser = new JSONParser();
        JSONObject jobj;
        String fileName = accountName + ".pkey";
        try {
            jobj = (JSONObject) parser.parse(new FileReader(fileName));
        } catch (ParseException e) {
            System.out.println("Cannot parse Json from file " + fileName);
            throw e;
        } catch (IOException e) {
            System.out.println("Cannot read from file " + fileName);
            throw e;
        }
        try {
            return Hex.decodeHex(((String) jobj.get("privkey")).toCharArray());
        } catch (DecoderException e) {
            System.out.println("Cannot decode private key");
            throw e;
        }
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
            if (m.getName().equals("main")
                    || m.getName().equals("displayFunctions")
                    || m.getName().equals("getECKeyByName")
                    || m.getName().equals("waitingForTransaction")
                    || m.getName().equals("genBalanceMsgHashSig")
                    || m.getName().equals("genClosingMsgHashSig")
                    || m.getName().equals("getClosingMsgHash")
                    || m.getName().equals("getBalanceMsgHash")) {
                continue;
            }

            String params = "";
            Class pvec[] = m.getParameterTypes();
            for (int j = 0; j < pvec.length; j++) {
                params = params + pvec[j];
                if (j < (pvec.length - 1)) {
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

            JSONObject jsonObject = (JSONObject) obj;
            for (Object key : jsonObject.keySet()) {
                switch ((String) key) {
                    case "debugInfo":
                        debugInfo = jsonObject.get(key).equals("true");
                        break;
                    case "gasPrice":
                        gasPrice = new BigInteger((String) jsonObject.get(key), 10);
                        if (debugInfo) {
                            System.out.println("The global gas price is set to be " + gasPrice.toString(10));
                        }
                        break;
                    case "rpcAddress":
                        rpcAddress = ((String) jsonObject.get(key));
                        if (debugInfo) {
                            System.out.println("rpcAddress = " + rpcAddress);
                        }
                        break;
                    case "channelAddr":
                        channelAddr = ((String) jsonObject.get(key));
                        if (debugInfo) {
                            System.out.println("channelAddr = " + channelAddr);
                        }
                        break;
                    case "tokenAddr":
                        tokenAddr = ((String) jsonObject.get(key));
                        if (debugInfo) {
                            System.out.println("tokenAddr = " + tokenAddr);
                        }
                        break;
                    case "channelABI":
                        String channelABI = ((String) jsonObject.get(key));
                        if (debugInfo) {
                            System.out.println("channelABI = " + channelABI);
                        }
                        channelContract = new CallTransaction.Contract(channelABI);
                        break;
                    case "tokenABI":
                        String tokenABI = ((String) jsonObject.get(key));
                        if (debugInfo) {
                            System.out.println("tokenABI = " + tokenABI);
                        }
                        tokenContract = new CallTransaction.Contract(tokenABI);
                        break;
                    case "appendingZerosForETH":
                        appendingZerosForETH = ((String) jsonObject.get(key));
                        if (debugInfo) {
                            System.out.println("appendingZerosForETH = " + appendingZerosForETH);
                        }
                        break;
                    case "appendingZerosForTKN":
                        appendingZerosForTKN = ((String) jsonObject.get(key));
                        if (debugInfo) {
                            System.out.println("appendingZerosForTKN = " + appendingZerosForTKN);
                        }
                        break;
                    case "maxDepositBits":
                        MAX_DEPOSIT = new BigInteger("2", 10).pow(Integer.parseInt(((String) jsonObject.get(key))));
                        gasPrice = new BigInteger((String) jsonObject.get(key), 10);
                        if (debugInfo) {
                            System.out.println("MAX_DEPOSIT =" + MAX_DEPOSIT.toString(16));
                        }
                        break;

                    default:
                        System.out.println("Unknown key is detected when parsing the configuration files.");
                }
                httpAgent = new Http(rpcAddress, debugInfo);
                token = new Token(tokenContract, tokenAddr, appendingZerosForTKN, appendingZerosForETH, gasPrice, httpAgent, debugInfo);
                transferChannel = new TransferChannel(channelAddr, channelContract, MAX_DEPOSIT, token, gasPrice, httpAgent, debugInfo);
            }
        } catch (FileNotFoundException e) {

        } catch (ParseException e) {
            System.out.println("Couldn't parse contents in m-ethereum.conf as a JSON object." + e);
        } catch (IOException e) {
            System.out.println("Couldn't parse contents in m-ethereum.conf as a JSON object." + e);
        }

        if (args.length < 1) {
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
            if (m.getName().equals(functionName)) {
                method = m;
                break;
            }
        }

        //cast the args to the correct type for the function params
        //note if you use a weird type this will probably shit itself.
        Object arglist[] = new Object[args.length - 1];
        Class pvec[] = method.getParameterTypes();
        for (int i = 1; i < args.length; i++) {
            if (pvec.length < i) {
                break;
            }

            String argtype = args[i].getClass().getName();
            String actualType = pvec[i - 1].getName();
            if (!argtype.equals(actualType)) {
                switch (actualType) {
                    case "int": {
                        arglist[i - 1] = Integer.parseInt(args[i]);
                        break;
                    }
                    default: {
                        System.out.println("UNKNOWN PARAM TYPE: " + actualType);
                        return;
                    }
                }
            } else {
                arglist[i - 1] = args[i];
            }
        }

        Object retobj = method.invoke(mr, arglist);
    }
}
