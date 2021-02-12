package de.nutrisafe;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.support.PersistenceExceptionTranslator;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.apache.commons.cli.*;

import java.util.Map;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
@PropertySource("classpath:application.properties")
//@ComponentScan(basePackages = {"de.nutrisafe"})
public class Main implements WebMvcConfigurer {

    static String mspId = "DeoniMSP";
    static String connectionJson;
    static String privateKey;
    static String adminCert;

    @SuppressFBWarnings({"WMI_WRONG_MAP_ITERATOR", "SF_SWITCH_NO_DEFAULT"})
    public static void main(String[] args) {
        Map<String, String> env = System.getenv();
        for (String e : env.keySet()) {
            switch (e) {
                case "CONNECTION_JSON" -> connectionJson = env.get(e);
                case "PRIVATE_KEY" -> privateKey = env.get(e);
                case "ADMIN_CERT" -> adminCert = env.get(e);
            }
        }

        // Define Options
        Options options = new Options();

        Option mspIdOption = new Option("msp", "msp_id", true, "Sets the name in the Membership Service Provider of the network.");
        mspIdOption.setRequired(false);
        options.addOption(mspIdOption);

        Option connectionJsonOption = new Option("con", "connection_json", true, "Sets the path to the connection definition file in JSON format.");
        connectionJsonOption.setRequired(false);
        options.addOption(connectionJsonOption);

        Option privateKeyOption = new Option("pk", "private_key", true, "Sets the private key path of this blockchain member.");
        privateKeyOption.setRequired(false);
        options.addOption(privateKeyOption);

        Option adminCertOption = new Option("cert", "admin_certificate", true, "Sets the path to the certificate.");
        adminCertOption.setRequired(false);
        options.addOption(adminCertOption);

        // Parse Options
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);

            mspId = cmd.getOptionValue("msp_id");
            connectionJson = cmd.getOptionValue("connection_json");
            privateKey = cmd.getOptionValue("private_key");
            adminCert = cmd.getOptionValue("admin_certificate");

            System.out.println("Starting REST API with the following configurations " +
                    " \n MSP ID: " + mspId +
                    " \n Connection path: " + connectionJson +
                    " \n Private key: " + privateKey +
                    " \n Admin Cert: " + adminCert);

            SpringApplication.run(Main.class, args);
        } catch(ParseException e) {
            System.err.println(e.getMessage());
            formatter.printHelp("NutriSafe REST API", options);
        }
    }

    @Bean
    public PersistenceExceptionTranslator persistenceExceptionTranslator() {
        return e -> new DataAccessException(e.getLocalizedMessage(), e) {
        };
    }

}
