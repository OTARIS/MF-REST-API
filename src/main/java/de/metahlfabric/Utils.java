package de.metahlfabric;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.io.IOUtils;
import org.hyperledger.fabric.gateway.*;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Utils {

    public ExecutorService executorService = Executors.newCachedThreadPool();

    private HyperledgerConfig config;
    private Network network = null;
    private String alarmFlag = null;
    Consumer<ContractEvent> alarmConsumer = null;

    public Utils(HyperledgerConfig config) {
        this.config = config;
    }

    private Wallet loadWallet() throws IOException {
        Wallet wallet = Wallets.newInMemoryWallet();
        wallet.put(config.getOrg(), Identities.newX509Identity(config.getOrg(),
                Objects.requireNonNull(loadCertificate()),
                Objects.requireNonNull(loadPrivateKey())));
        return wallet;

    }

    private X509Certificate loadCertificate() {
        try {
            FileInputStream fileInputStream = new FileInputStream(config.getCert());
            byte[] encodedCert = IOUtils.toByteArray(fileInputStream);
            //ClassPathResource classPathResource = new ClassPathResource(config.getCertPath());
            //byte[] encodedCert = FileCopyUtils.copyToByteArray(classPathResource.getInputStream());
            ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (Exception e) {
            System.err.println("[MF] Could not load certificate.");
            e.printStackTrace();
        }
        return null;
    }

    private PrivateKey loadPrivateKey() {
        try {
            FileInputStream fileInputStream = new FileInputStream(config.getPk());
            //ClassPathResource classPathResource = new ClassPathResource(config.getPrivateKeyPath());
            //InputStream ci = classPathResource.getInputStream();
            String privateKeyPEM = IOUtils.toString(fileInputStream, UTF_8);
            privateKeyPEM = privateKeyPEM.replaceAll("-----BEGIN PRIVATE KEY-----", "");
            privateKeyPEM = privateKeyPEM.replaceAll("-----END PRIVATE KEY-----", "");
            privateKeyPEM = privateKeyPEM.replace("\n", "").replace("\r", "");
            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return kf.generatePrivate(keySpec);
        } catch (Exception e) {
            System.err.println("[MF] Could not load private key.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Setting up a connection to the "NutriSafe" Network.
     *
     * @return returning the contract which is used for submitting or evaluate a transaction.
     */
    private Contract prepareTransaction() throws IOException {
        Contract contract = null;
        FileInputStream fileInputStream = null;
        try {
            /*
             * Preparing a builder for our Gateway.
             * .discovery(): Service discovery for all transaction submissions is enabled.
             */
            if (network == null) {
                alarmConsumer = null;
                fileInputStream = new FileInputStream(config.getNetwork());
                //ClassPathResource classPathResource = new ClassPathResource(config.getNetworkConfigPath());
                Gateway.Builder builder = Gateway.createBuilder()
                        .identity(loadWallet(), config.getOrg())
                        .networkConfig(fileInputStream);
                        //.discovery(true);
                Gateway gateway = builder.connect();

                network = gateway.getNetwork(config.getChannel());
            }
            contract = network.getContract(config.getChaincode());
            if(alarmConsumer == null)
                alarmConsumer = contract.addContractListener(this::alarmActivated,
                        Pattern.compile("alarm", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));

        } catch (IOException e) {
            System.err.println("[MF] Could not prepare the transaction.");
            e.printStackTrace();
        } finally {
            if (fileInputStream != null)
                fileInputStream.close();

        }
        return contract;
    }

    public String submitTransaction(final String function, String[] args, HashMap<String, byte[]> pArgs) {
        String ret = "";
        try {
            Contract contract = prepareTransaction();
            if (contract == null) throw new IOException();

            final byte[] result;
            if (pArgs.size() == 0) {
                result = contract.createTransaction(function)
                        .submit(args);
            } else {
                result = contract.createTransaction(function)
                        .setTransient(pArgs)
                        .submit(args);
            }
            ret = new String(result, UTF_8);

        } catch (IOException | TimeoutException | ContractException | InterruptedException e) {
            System.err.println("[MF] Could not submit the transaction.");
            e.printStackTrace();
        }
        return ret;
    }

    public String evaluateTransaction(final String function, final String[] args) throws Exception {
        String ret = "";
        try {
            Contract contract = prepareTransaction();
            if (contract == null) throw new IOException();
            byte[] result;
            if (args == null) {
                result = contract.evaluateTransaction(function);
            } else {
                result = contract.evaluateTransaction(function, args);
            }
            System.out.println(new String(result, UTF_8));
            ret = new String(result, UTF_8);

        } catch (IOException | ContractException e) {
            System.err.println("[MF] Could not evaluate the transaction.");
            e.printStackTrace();
        }
        return ret;
    }

    public String getAlarmFlag() {
        return this.alarmFlag;
    }

    public void resetAlarmFlag() {
        alarmFlag = null;
    }

    public void alarmActivated(ContractEvent e) {
        String pl = new String(e.getPayload().get(), UTF_8);
        JsonObject ret = (JsonObject) JsonParser.parseString(pl);
        alarmFlag = ret.get("key").toString();
        executorService.notifyAll();
    }
}
