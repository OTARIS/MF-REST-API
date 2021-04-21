package de.metahlfabric;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.support.PersistenceExceptionTranslator;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.apache.commons.cli.*;

import java.util.Map;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
@PropertySource("classpath:application.properties")
//@ComponentScan(basePackages = {"de.nutrisafe"})
public class Main implements WebMvcConfigurer {

    private final static String MF_PROPERTIES = "MF_PROPERTIES";
    private final static String ORG = "organization";
    private final static String PROPERTIES = "properties_file";
    private final static String PRIVATE_KEY = "private_key";
    private final static String CERTIFICATE = "certificate";
    private final static String DB_NAME = "database_name";
    private final static String DB_USER = "database_user";
    private final static String DB_PASS = "database_password";

    static String org = null;
    static String propertiesFile = null;
    static String privateKey = null;
    static String adminCert = null;
    static String dbUser = null;
    static String dbPass = null;
    static String dbName = null;

    @SuppressFBWarnings({"WMI_WRONG_MAP_ITERATOR"})
    public static void main(String[] args) {
        Map<String, String> env = System.getenv();
        if(env.containsKey(MF_PROPERTIES))
            propertiesFile = env.get(MF_PROPERTIES);

        // Define Options
        Options options = new Options();

        Option mspIdOption = new Option("org", ORG, true, "The name of your organization in the Membership Service Provider (MSP) of the blockchain network.");
        mspIdOption.setRequired(false);
        options.addOption(mspIdOption);

        Option propertyOption = new Option("prop", PROPERTIES, true, "Sets the path to the property file. Alternatively, you can use the environment variable '" + MF_PROPERTIES + "'.");
        propertyOption.setRequired(propertiesFile == null);
        options.addOption(propertyOption);

        Option privateKeyOption = new Option("pk", PRIVATE_KEY, true, "Sets the private key path of this blockchain network member.");
        privateKeyOption.setRequired(false);
        options.addOption(privateKeyOption);

        Option adminCertOption = new Option("cert", CERTIFICATE, true, "Sets the path to the certificate file of this blockchain network member.");
        adminCertOption.setRequired(false);
        options.addOption(adminCertOption);

        Option dbNameOption = new Option("db_name", DB_NAME, true, "Configures the name of the user database.");
        dbNameOption.setRequired(false);
        options.addOption(dbNameOption);

        Option dbUserOption = new Option("db_user", DB_USER, true, "Configures the user name for accessing the user database.");
        dbUserOption.setRequired(false);
        options.addOption(dbUserOption);

        Option dbPassOption = new Option("db_pass", DB_PASS, true, "Configures the password for accessing the user database.");
        dbPassOption.setRequired(false);
        options.addOption(dbPassOption);

        // Parse Options
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);

            org = cmd.getOptionValue(ORG);
            propertiesFile = cmd.getOptionValue(PROPERTIES);
            privateKey = cmd.getOptionValue(PRIVATE_KEY);
            adminCert = cmd.getOptionValue(CERTIFICATE);
            dbName = cmd.getOptionValue(DB_NAME);
            dbUser = cmd.getOptionValue(DB_USER);
            dbPass = cmd.getOptionValue(DB_PASS);

            SpringApplication.run(Main.class, args);
        } catch(ParseException e) {
            System.err.println(e.getMessage());
            formatter.printHelp("MetaHL Fabric", options);
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
        if(propertiesFile != null) {
            Resource[] resources = new Resource[ ]
                    { new ClassPathResource("application.properties"), new ClassPathResource("application.yml"),
                            new FileSystemResource(propertiesFile)  };
            properties.setLocations(resources);
        }
        properties.setIgnoreResourceNotFound(false);
        return properties;
    }

}
