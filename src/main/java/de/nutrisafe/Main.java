package de.nutrisafe;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.FileSystemResource;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.support.PersistenceExceptionTranslator;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.apache.commons.cli.*;

import java.util.Map;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
@PropertySource("classpath:application.properties")
//@ComponentScan(basePackages = {"de.nutrisafe"})
public class Main implements WebMvcConfigurer {

    private final static String NUTRISAFE_PROPERTY = "NUTRISAFE_PROPERTY";
    private final static String NUTRISAFE_PRIVATE_KEY = "NUTRISAFE_PRIVATE_KEY";
    private final static String NUTRISAFE_CERT = "NUTRISAFE_CERT";
    private final static String MSP = "msp_id";
    private final static String PROPERTY = "property_file";
    private final static String PRIVATE_KEY = "private_key";
    private final static String CERTIFICATE = "certificate";
    private final static String DB_NAME = "database_name";
    private final static String DB_USER = "database_user";
    private final static String DB_PASS = "database_password";

    static String mspId = null;
    static String propertyPath = null;
    static String privateKey = null;
    static String adminCert = null;
    static String dbUser = null;
    static String dbPass = null;
    static String dbName = null;

    @SuppressFBWarnings({"WMI_WRONG_MAP_ITERATOR", "SF_SWITCH_NO_DEFAULT"})
    public static void main(String[] args) {
        Map<String, String> env = System.getenv();
        if(env.containsKey(NUTRISAFE_PROPERTY))
            propertyPath = env.get(NUTRISAFE_PROPERTY);
        if(env.containsKey(NUTRISAFE_PRIVATE_KEY))
            privateKey = env.get(NUTRISAFE_PRIVATE_KEY);
        if(env.containsKey(NUTRISAFE_CERT))
            adminCert = env.get(NUTRISAFE_CERT);

        // Define Options
        Options options = new Options();

        Option mspIdOption = new Option("msp", MSP, true, "The name of your organization in the Membership Service Provider (MSP) of the blockchain network.");
        mspIdOption.setRequired(false);
        options.addOption(mspIdOption);

        Option propertyOption = new Option("prop", PROPERTY, true, "Sets the path to the property file.");
        propertyOption.setRequired(propertyPath == null);
        options.addOption(propertyOption);

        Option privateKeyOption = new Option("pk", PRIVATE_KEY, true, "Sets the private key path of this blockchain network member.");
        privateKeyOption.setRequired(false);
        options.addOption(privateKeyOption);

        Option adminCertOption = new Option("cert", CERTIFICATE, true, "Sets the path to the certificate file of this blockchain network member.");
        adminCertOption.setRequired(false);
        options.addOption(adminCertOption);

        Option dbNameOption = new Option("db-name", DB_NAME, true, "Configures the name of the user database.");
        dbNameOption.setRequired(false);
        options.addOption(dbNameOption);

        Option dbUserOption = new Option("db-user", DB_USER, true, "Configures the user name for accessing the user database.");
        dbUserOption.setRequired(false);
        options.addOption(dbUserOption);

        Option dbPassOption = new Option("db-pass", DB_PASS, true, "Configures the password for accessing the user database.");
        dbPassOption.setRequired(false);
        options.addOption(dbPassOption);

        // Parse Options
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);

            mspId = cmd.getOptionValue(MSP);
            propertyPath = cmd.getOptionValue(PROPERTY);
            privateKey = cmd.getOptionValue(PRIVATE_KEY);
            adminCert = cmd.getOptionValue(CERTIFICATE);
            dbName = cmd.getOptionValue(DB_NAME);
            dbUser = cmd.getOptionValue(DB_USER);
            dbPass = cmd.getOptionValue(DB_PASS);

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

    @Bean
    public PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        PropertySourcesPlaceholderConfigurer properties =
                new PropertySourcesPlaceholderConfigurer();
        if(propertyPath != null)
            properties.setLocation(new FileSystemResource(propertyPath));
        properties.setIgnoreResourceNotFound(false);
        return properties;
    }

}
