package io.security.springsecuritymaster;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    /*
        - Authentication Events
          • 스프링 시큐리티는 인증이 성공하거나 실패하게 되면 AuthenticationSuccessEvent 또는 AuthenticationFailureEvent 를 발생시킨다
          • 이벤트를 수신하려면 ApplicationEventPublisher 를 사용하거나 시큐리티에서 제공하는 AuthenticationEventPublisher 를 사용해서 발행해야 한다
          • AuthenticationEventPublisher 의 구현체로 DefaultAuthenticationEventPublisher 가 제공된다
          • 스프링의 이벤트 리스닝 메커니즘은 자바의 클래스 상속 구조를 따르기 때문에 특정 이벤트의 리스너는 해당 이벤트 뿐만 아니라
            그 이벤트의 부모 클래스 (또는 인터페이스)들로부터 발생하는 이벤트도 처리 할 수 있다
     */


    /** 1. ApplicationEventPublisher 사용방법. */
//    private final ApplicationContext applicationContext;
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/user").hasAuthority("ROLE_USER")
//                        .requestMatchers("/db").hasAuthority("ROLE_DB")
//                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
//                        .anyRequest().permitAll())
//                .formLogin(form -> form
//                        .successHandler((request, response, authentication) -> { // 성공했을 때 이벤트 발생 로직
//                            applicationContext.publishEvent(new CustomAuthenticationSuccessEvent(authentication));
//                            response.sendRedirect("/");
//                        }))
//                .csrf(AbstractHttpConfigurer::disable)
//              //  .authenticationProvider(authenticationProvider); // CustomAuthenticationProvider을 @Component 어노테이션을 통해 빈으로 등록하여 사용하면, 여기서 기술하지 않아도 된다.
//        ;
//
//        return http.build();
//    }


    /** 2. AuthenticationEventPublisher 사용방법. */
    private final ApplicationContext applicationContext;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/db").hasAuthority("ROLE_DB")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().permitAll())
                .formLogin(form -> form
                        .successHandler((request, response, authentication) -> { // 성공했을 때 이벤트 발생 로직
                            applicationContext.publishEvent(new CustomAuthenticationSuccessEvent(authentication));
                            response.sendRedirect("/");
                        }))
                .csrf(AbstractHttpConfigurer::disable)
                .authenticationProvider(customAuthenticationProvider2())
        ;

        return http.build();
    }

    @Bean
    public AuthenticationProvider customAuthenticationProvider2() {
        return new CustomAuthenticationProvider2(authenticationEventPublisher(null));
    }

    @Bean
    public DefaultAuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        DefaultAuthenticationEventPublisher authenticationEventPublisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);
        return authenticationEventPublisher;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails db = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "SECURE").build();
        return new InMemoryUserDetailsManager(user, db, admin);
    }

}
