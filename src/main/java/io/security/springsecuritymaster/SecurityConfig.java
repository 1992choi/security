package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - Custom AuthorizationManager
              • 스프링 시큐리티 인가 설정 시 선언적 방식이 아닌 프로그래밍 방식으로 구현할 수 있으며 access(AuthorizationManager) API 를 사용한다
              • access() 에는 AuthorizationManager<RequestAuthorizationContext> 타입의 객체를 전달할 수 있으며 사용자의 요청에 대한 권한 검사를 access()에 지정한 AuthorizationManager 가 처리하게 된다
              • access() 에 지정한 AuthorizationManager 객체는 RequestMatcherDelegatingAuthorizationManager 의 매핑 속성에 저장된다
              • 만약 코드가 아래와 같다면, "/api" 요청 패턴의 권한 검사는 CustomAuthorizationManager 가 처리한다.
                나머지는 AuthorityAuthorizationManager 가 처리

                Ex) http.authorizeHttpRequests(auth -> auth
                         .requestMatchers("/user", "/myPage").hasAuthority("USER")
                         .requestMatchers("/admin").hasRole("ADMIN")
                         .requestMatchers("/api").access(new CustomAuthorizationManager()));
         */

        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user").hasRole("USER")
                        .requestMatchers("/db").access(new WebExpressionAuthorizationManager("hasRole('DB')"))
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/secure").access(new CustomAuthorizationManager())
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails db = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "SECURE").build();
        return new InMemoryUserDetailsManager(user, db, admin);
    }

}
