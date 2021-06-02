package de.metahlfabric;

import de.metahlfabric.functionrights.FunctionRightProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.JwtAccessTokenConverterConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Map;

/**
 * This is a resource server for OAuth.
 *
 * @author Kathrin Kleinhammer
 *
 * Copyright 2021 OTARIS Interactive Services GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private FunctionRightProvider functionRightProvider;

    @Override
    public void configure(ResourceServerSecurityConfigurer config) {
        config.tokenServices(createTokenServices());
    }

    @Bean
    public DefaultTokenServices createTokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(createTokenStore());
        return defaultTokenServices;
    }

    @Bean
    public TokenStore createTokenStore() {
        return new JwtTokenStore(createJwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter createJwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setAccessTokenConverter(new JwtConverter());
        return converter;
    }

    public static class JwtConverter extends DefaultAccessTokenConverter implements JwtAccessTokenConverterConfigurer {

        @Override
        public void configure(JwtAccessTokenConverter converter) {
            converter.setAccessTokenConverter(this);
        }

        @Override
        public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
            OAuth2Authentication auth = super.extractAuthentication(map);
            auth.setDetails(map);
            return auth;
        }
    }
}
