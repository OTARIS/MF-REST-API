package de.nutrisafe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.support.PersistenceExceptionTranslator;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Map;

@SpringBootApplication(exclude={DataSourceAutoConfiguration.class})
@PropertySource("classpath:application.properties")
//@ComponentScan(basePackages = {"de.nutrisafe"})
public class Main implements WebMvcConfigurer {

    public static String mspId = "DeoniMSP";
    public static String connectionJson;
    public static String privateKey;
    public static String adminCert;

    public static void main(String[] args) {
        Map<String, String> env = System.getenv();
        for(String e : env.keySet()){
            switch (e) {
                case "CONNECTION_JSON" -> connectionJson = env.get(e);
                case "PRIVATE_KEY" -> privateKey = env.get(e);
                case "ADMIN_CERT" -> adminCert = env.get(e);
            }
        }
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
