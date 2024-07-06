package io.security.springsecuritymaster;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /*
        - 표현식 권한 규칙 설정
          • 스프링 시큐리티는 표현식을 사용해서 권한 규칙을 설정하도록 WebExpressionAuthorizationManager 를 제공한다.
          • 표현식은 시큐리티가 제공하는 권한 규칙을 사용하거나 사용자가 표현식을 커스텀하게 구현해서 설정 가능하다.

        - 사용 방법
          • requestMatchers().access(new WebExpressionAuthorizationManager("expression"))
          • Ex) // 요청으로부터 값을 추출할 수 있다
                requestMatchers("/resource/{name}").access(new WebExpressionAuthorizationManager("#name == authentication.name")

                // 여러개의 권한 규칙을 조합할 수 있다
                requestMatchers("/admin/db").access(new WebExpressionAuthorizationManager("hasAuthority('DB') or hasRole('ADMIN')"))
                => 다음과 도일한 규칙이다. : requestMatchers("/admin/db").access(anyOf(hasAuthority("db"), hasRole("ADMIN")))

     */

    // 표현식 사용 예제 (기본 제공 표현식)
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user/{name}")
                        .access(new WebExpressionAuthorizationManager("#name == authentication.name"))

                        .requestMatchers("/admin/db")
                        .access(new WebExpressionAuthorizationManager("hasAuthority('ROLE_DB') or hasRole('ADMIN')"))

                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }



    // 표현식 사용 예제 (커스텀 표현식)
    // 사용자 정의 빈을 생성하고 새로운 표현식으로 사용할 메서드를 정의하고 권한 검사 로직을 구현한다
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {
//        DefaultHttpSecurityExpressionHandler expressionHandler = new DefaultHttpSecurityExpressionHandler();
//        expressionHandler.setApplicationContext(context);
//
//        WebExpressionAuthorizationManager expressManager = new WebExpressionAuthorizationManager("@customWebSecurity.check(authentication, request)");
//        expressManager.setExpressionHandler(expressionHandler);
//
//        http.authorizeHttpRequests(authorize -> authorize
//                .requestMatchers("/custom/**").access(expressManager)
//                .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }



    // 커스텀 RequestMatcher 예제
    // RequestMatcher 의 macher 및 matches 메서드를 사용하여 클라이언트의 요청객체로부터 값을 검증하도록 커스텀한 RequestMatcher를 구현하고 requestMatchers() 메서드에 설정한다.
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {
//        http.authorizeHttpRequests(authorize -> authorize
//                .requestMatchers(new CustomRequestMatcher("/admin")).hasAuthority("ROLE_ADMIN")
//                .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }



    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails db = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "SECURE").build();
        return new InMemoryUserDetailsManager(user, db, admin);
    }

}
