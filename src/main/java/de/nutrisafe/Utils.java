package de.nutrisafe;

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
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Utils {

    private Config config;
    private Network network = null;
    private Gateway gateway = null;
    private String alarmFlag = null;

    public Utils(Config config) {
        this.config = config;
    }

    private Wallet loadWallet() throws IOException {
        Wallet wallet = Wallets.newInMemoryWallet();
        wallet.put(config.getCompany(), Identities.newX509Identity(config.getCompany(),
                Objects.requireNonNull(loadCertificate()),
                Objects.requireNonNull(loadPrivateKey())));
        return wallet;

    }

    private X509Certificate loadCertificate() {
        try {
            FileInputStream fileInputStream = new FileInputStream(config.getCertPath());
            byte[] encodedCert = IOUtils.toByteArray(fileInputStream);
            //ClassPathResource classPathResource = new ClassPathResource(config.getCertPath());
            //byte[] encodedCert = FileCopyUtils.copyToByteArray(classPathResource.getInputStream());
            ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (Exception e) {
            System.err.println("[NutriSafe REST API] Could not load certificate.");
            e.printStackTrace();
        }
        return null;
    }

    private PrivateKey loadPrivateKey() {
        try {
            FileInputStream fileInputStream = new FileInputStream(config.getPrivateKeyPath());
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
            System.err.println("[NutriSafe REST API] Could not load private key.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Setting up a connection to the "NutriSafe" Network.
     * @return returning the contract which is used for submitting or evaluate a transaction.
     */
    private Contract prepareTransaction() {
        Contract contract = null;
        try {
            /*
             * Preparing a builder for our Gateway.
             * .discovery(): Service discovery for all transaction submissions is enabled.
            */
            if(network == null) {
                FileInputStream fileInputStream = new FileInputStream(config.getNetworkConfigPath());
                //ClassPathResource classPathResource = new ClassPathResource(config.getNetworkConfigPath());
                Gateway.Builder builder = Gateway.createBuilder()
                        .identity(loadWallet(), config.getCompany())
                        .networkConfig(fileInputStream);
                //.discovery(true);
                gateway = builder.connect();

                network = gateway.getNetwork(config.getChannelName());
            }
            contract = network.getContract(config.getChaincodeName());

        } catch (IOException e) {
            System.err.println("[NutriSafe REST API] Could not prepare the transaction.");
            e.printStackTrace();
        }
        return contract;
    }

    public String submitTransaction(final String function, String[] args, HashMap<String, byte[]> pArgs) {
        String ret = "";
        try {
            Contract contract = prepareTransaction();

            //Consumer<ContractEvent> listener = contract.addContractListener(contractEvent -> System.out.println(contractEvent.getName()));
            Consumer<ContractEvent> listener = contract.addContractListener(contractEvent -> alarmFlag = "ALARM");

            if(contract == null) throw new IOException();
            final byte[] result;
            if (pArgs.size() == 0){
                result = contract.createTransaction(function)
                        .submit(args);
            }
            else {
                result = contract.createTransaction(function)
                        .setTransient(pArgs)
                        .submit(args);
            }
            ret = new String(result, UTF_8);

        } catch (IOException | TimeoutException | ContractException | InterruptedException e) {
            e.printStackTrace();
            System.out.println(e);
        }
        return ret;
    }

    public String evaluateTransaction(final String function, final String[] args) throws Exception {
        String ret = "";
        try {
            Contract contract = prepareTransaction();
            if(contract == null) throw new IOException();
            byte[] result;
            if (args == null){
                result = contract.evaluateTransaction(function);
            }
            else {
                result = contract.evaluateTransaction(function, args);
            }
            System.out.println(new String(result, UTF_8));
            ret = new String(result, UTF_8);

        } catch (IOException | ContractException e) {
            e.printStackTrace();
            System.out.println(e);
        }
        return ret;
    }

    String getAlarmFlag(){
        return this.alarmFlag;
    }
}
