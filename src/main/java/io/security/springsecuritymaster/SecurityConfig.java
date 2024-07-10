package io.security.springsecuritymaster;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;
import java.util.Map;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/db").hasAuthority("ROLE_DB")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .authenticationProvider(customAuthenticationProvider());

        return http.build();
    }

    @Bean
    public AuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider(customAuthenticationEventPublisher(null));
    }

    @Bean
    public AuthenticationEventPublisher customAuthenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        Map<Class<? extends AuthenticationException>, Class<? extends AbstractAuthenticationFailureEvent>> mapping =
                Collections.singletonMap(CustomException.class, CustomAuthenticationFailureEvent.class);

        DefaultAuthenticationEventPublisher authenticationEventPublisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);
        authenticationEventPublisher.setAdditionalExceptionMappings(mapping); // CustomException 을 던지면 CustomAuthenticationFailureEvent 를 발행하도록 추가 함
        authenticationEventPublisher.setDefaultAuthenticationFailureEvent(DefaultAuthenticationFailureEvent.class); // 매핑된 상태가 아닌 경우, 기본 이벤트가 발생하도록 처리
        return authenticationEventPublisher;

        /*
            - 매핑된 예외가 있는 경우 (admin으로 로그인하여 CustomException 발생 -> CustomAuthenticationFailureEvent 호출)
              [CustomAuthenticationFailureEvent] failures = CustomException
              [AbstractAuthenticationFailureEvent] failures = CustomException
              [CustomAuthenticationFailureEvent] failures = CustomException
              [AbstractAuthenticationFailureEvent] failures = CustomException
              [CustomAuthenticationFailureEvent] failures = CustomException
              [AbstractAuthenticationFailureEvent] failures = CustomException

            - 매핑된 예외가 없는 경우 (db로 로그인하여 InsufficientAuthenticationException 발생 -> DefaultAuthenticationFailureEvent 호출)
              [DefaultAuthenticationFailureEvent failures = CustomException
              [AbstractAuthenticationFailureEvent] failures = CustomException
              [DefaultAuthenticationFailureEvent failures = CustomException
              [AbstractAuthenticationFailureEvent] failures = CustomException
              [DefaultAuthenticationFailureEvent failures = CustomException
              [AbstractAuthenticationFailureEvent] failures = CustomException
         */
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails db = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "SECURE").build();
        return new InMemoryUserDetailsManager(user, db, admin);
    }
}