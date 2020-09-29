package de.nutrisafe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.PropertySource;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.support.PersistenceExceptionTranslator;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication(exclude={DataSourceAutoConfiguration.class})
@PropertySource("classpath:application.properties")
//@ComponentScan(basePackages = {"de.nutrisafe"})
public class Main implements WebMvcConfigurer {

    public static String mspId = "DeoniMSP";
    public static String connectionJson = "C:\\NutriSafe\\Zertifikate\\connection_deoni.json";
    public static String privateKey = "C:\\NutriSafe\\Zertifikate\\deoni_private_key";
    public static String adminCert = "C:\\NutriSafe\\Zertifikate\\deoni_admin_cert.pem";

    public static void main(String[] args) {
        if (args.length > 2){
            mspId = args[0];
            connectionJson = args[1];
            privateKey = args[2];
            adminCert = args[3];
        }
        System.out.println("Starting REST API with the following configurations " +
                " \n MSP ID: " + mspId +
                " \n Connection path: " + connectionJson +
                " \n Private key: " + privateKey +
                " \n Admin Cert: " + adminCert);

        SpringApplication.run(Main.class, args);
    }

    @Bean
    public PersistenceExceptionTranslator persistenceExceptionTranslator() {
        return e -> new DataAccessException(e.getLocalizedMessage(), e) {
        };
    }

}
