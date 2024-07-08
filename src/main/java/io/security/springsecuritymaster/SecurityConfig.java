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

    /*
        - 요청 기반 인가 관리자
          • 스프링 시큐리티는 요청 기반의 인증된 사용자 및 특정권한을 가진 사용자의 자원접근 허용여부를 결정하는 인가 관리자 클래스들을 제공한다
          • 대표적으로 AuthorityAuthorizationManager, AuthenticatedAuthorizationManager 와 대리자인 RequestMatcherDelegatingAuthorizationManager 가 있다

        - AuthenticatedAuthorizationManager 구조
          • AuthenticatedAuthorizationManager 는 내부적으로 네 개의 AbstractAuthorizationStrategy 구현을 통해 인증 여부 확인 전략을 세운다
            1. FullyAuthenticatedAuthorizationStrategy : 익명 인증 및 기억하기 인증이 아닌지 검사
            2. AuthenticatedAuthorizationStrategy : 인증된 사용자인지 검사
            3. RememberMeAuthorizationStrategy : 기억하기 인증인지 검사
            4. AnonymousAuthorizationStrategy : 익명 사용자인지 검사
          • Ex)  @Bean
                 SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
                     http.authorizeHttpRequests(auth -> auth
                         .requestMatchers("/user").authenticated()
                         .requestMatchers("/myPage").fullyAuthenticated()
                         .requestMatchers("/guest").anonymous()
                         .requestMatchers("/history").rememberMe());

                     return http.build();
                 }
                 --> AuthenticatedAuthorizationManager는 각 인증방식에 따라 적절한 AbstractAuthorizationStrategy를 선택(상위 4개 중 1개 선택)해서 인증 여부를 확인한다

        - AuthorityAuthorizationManager 구조
          • AuthorityAuthorizationManager는 내부적으로 AuthoritiesAuthorizationManager를 사용하여 권한 여부 결정을 위임한다
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user").hasRole("USER")
                        .requestMatchers("/db").access(new WebExpressionAuthorizationManager("hasRole('DB')"))
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
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
