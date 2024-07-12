package io.security.springsecuritymaster.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll()
                        .requestMatchers("/", "/signup").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login").permitAll());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        /*
            - 기본적으로 bcrypt 암호화 알고리즘의 BCryptPasswordEncoder 객체를 생성하고 사용.

            - 아래처럼 알고리즘을 지정할 수도 있다.
                Ex)
                String encodingId = "pbkdf2";
                Map<String, PasswordEncoder> encoders = new HashMap<>();
                encoders.put(encodingId, Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
                DelegatingPasswordEncoder delegatingPasswordEncoder = new DelegatingPasswordEncoder(encodingId, encoders);
                return delegatingPasswordEncoder;

            - 시큐리티 지원 암호화 알고리즘 유형
                String encodingId = "bcrypt";
                Map<String, PasswordEncoder> encoders = new HashMap<>();
                encoders.put(encodingId, new BCryptPasswordEncoder());
                encoders.put("ldap", new org.springframework.security.crypto.password.LdapShaPasswordEncoder());
                encoders.put("MD4", new org.springframework.security.crypto.password.Md4PasswordEncoder());
                encoders.put("MD5", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("MD5"));
                encoders.put("noop", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance());
                encoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_5());
                encoders.put("pbkdf2@SpringSecurity_v5_8", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
                encoders.put("scrypt", SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1());
                encoders.put("scrypt@SpringSecurity_v5_8", SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
                encoders.put("SHA-1", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-1"));
                encoders.put("SHA-256",
                new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-256"));
                encoders.put("sha256", new org.springframework.security.crypto.password.StandardPasswordEncoder());
                encoders.put("argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2());
                encoders.put("argon2@SpringSecurity_v5_8", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
         */
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }

}