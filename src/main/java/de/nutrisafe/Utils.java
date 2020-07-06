package de.nutrisafe;

import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.gateway.impl.InMemoryWallet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ResourceUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
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
import java.util.Objects;
import java.util.concurrent.TimeoutException;

public class Utils {

    @Autowired
    Config config;

    public Wallet loadWallet() throws IOException, CertificateException {
        Wallet wallet = new InMemoryWallet();
        wallet.put(config.getCompany(), Wallet.Identity.createIdentity(config.getCompany(),
                Objects.requireNonNull(loadCertificate()).toString(), loadPrivateKey()));
        return wallet;
    }

    private X509Certificate loadCertificate() throws CertificateException {
        try {
            File file = ResourceUtils.getFile("classpath:cert.cer");
            String base64Cert = new String(Files.readAllBytes(file.toPath()));
            byte[] encodedCert = Base64.getDecoder().decode(base64Cert);
            ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (IOException e) {
            System.err.println("[NutriSafe REST API] Could not load certificate.");
            e.printStackTrace();
        }
        return null;
    }

    public PrivateKey loadPrivateKey() {
        try {
            File file = ResourceUtils.getFile("classpath:private-key.pem");
            String privateKeyPEM = new String(Files.readAllBytes(file.toPath()));
            privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
            privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return kf.generatePrivate(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("[NutriSafe REST API] Could not load private key.");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Setting up a connection to the "NutriSafe" Network.
     * @param contract_p the contract proposal
     * @return returning the contract which is used for submitting or evaluate a transaction.
     */
    private Contract prepareTransaction(final String contract_p) {
        Contract contract = null;
        try {
            /*
             * Preparing a builder for our Gateway.
             * .discovery(): Service discovery for all transaction submissions is enabled.
             */
            Gateway.Builder builder = Gateway.createBuilder()
                    .identity(loadWallet(), config.getCompany())
                    .networkConfig(Paths.get(config.getNetworkConfigPath()))
                    .discovery(true);

            final Gateway gateway = builder.connect();

            final Network network = gateway.getNetwork(config.getDefaultNetwork());

            contract = network.getContract(contract_p);

        } catch (IOException | CertificateException e) {
            System.err.println("Could not prepare the transaction.");
            e.printStackTrace();
        }
        return contract;
    }

    public String submitTransaction(final String contract_p, final String[] query) {
        String ret = "";
        try {
            Contract contract = prepareTransaction(contract_p);
            if(contract == null) throw new IOException();

            final byte[] result = contract.submitTransaction(Arrays.toString(query));

            ret = Arrays.toString(result);

        } catch (IOException | TimeoutException | ContractException | InterruptedException e) {
            e.printStackTrace();
        }

        return ret;
    }

    public String evaluateTransaction(final String contract_p, final String[] query) {
        String ret = "";
        try {
            Contract contract = prepareTransaction(contract_p);
            if(contract == null) throw new IOException();

            final byte[] result = contract.evaluateTransaction(Arrays.toString(query));

            ret = Arrays.toString(result);

        } catch (IOException | ContractException e) {
            e.printStackTrace();
        }

        return ret;
    }
}
