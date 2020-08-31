package de.nutrisafe;

import org.hyperledger.fabric.gateway.*;
//import org.hyperledger.fabric.gateway.impl.InMemoryWallet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ResourceUtils;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.TimeoutException;

public class Utils {

    Config config;

    public Wallet loadWallet() throws IOException, CertificateException {
        Wallet wallet = Wallets.newInMemoryWallet();
        wallet.put(config.getCompany(), Identities.newX509Identity(config.getCompany(), loadCertificate(), loadPrivateKey()));
        return wallet;
    }



    private X509Certificate loadCertificate() throws CertificateException {
        try {
            //TODO: Zertifakte sollten über config geladen werden (Problem siehe oben)
            File file = ResourceUtils.getFile("classpath:" + config.getCertPath());
            byte[] encodedCert = Files.readAllBytes(file.toPath());
            ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (Exception e) {
            System.err.println("[NutriSafe REST API] Could not load certificate.");
            e.printStackTrace();
        }
        return null;
    }

    public PrivateKey loadPrivateKey() {
        try {
            File file = ResourceUtils.getFile("classpath:" + config.getPrivateKeyPath());
            String privateKeyPEM = new String(Files.readAllBytes(file.toPath()));
            privateKeyPEM = privateKeyPEM.replaceAll("\\n|-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----", "");
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
            Path networkConfigFile = ResourceUtils.getFile("classpath:" + config.getNetworkConfigPath()).toPath();
            Gateway.Builder builder = Gateway.createBuilder()
                    .identity(loadWallet(), config.getCompany())
                    .networkConfig(networkConfigFile);
                    //.discovery(true);

            final Gateway gateway = builder.connect();

            final Network network = gateway.getNetwork(config.getChannelName());

            contract = network.getContract(config.getChaincodeName());

        } catch (IOException | CertificateException e) {
            System.err.println("Could not prepare the transaction.");
            e.printStackTrace();
        }
        return contract;
    }

    public String submitTransaction(Config config, final String function, String[] args, HashMap<String, byte[]> pArgs) {
        this.config = config;
        String ret = "";
        try {
            Contract contract = prepareTransaction();
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
            ret = new String(result, StandardCharsets.UTF_8);

        } catch (IOException | TimeoutException | ContractException | InterruptedException e) {
            e.printStackTrace();
            System.out.println(e);
        }
        return ret;
    }

    public String evaluateTransaction(Config config, final String function, final String[] args) throws Exception {
        this.config = config;
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
            System.out.println(new String(result, StandardCharsets.UTF_8));
            ret = new String(result, StandardCharsets.UTF_8);

        } catch (IOException | ContractException e) {
            e.printStackTrace();
            System.out.println(e);
        }
        return ret;
    }
}
