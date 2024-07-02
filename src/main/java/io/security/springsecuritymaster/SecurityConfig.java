package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /**
     * AuthenticationProvider 사용 방법 - 일반 객체로 생성
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - AuthenticationProvider
                • 사용자의 자격 증명을 확인하고 인증 과정을 관리하는 클래스로서 사용자가 시스템에 액세스하기 위해 제공한 정보(예: 아이디와 비밀번호)가 유효한지 검증하는 과정을 포함한다
                • 다양한 유형의 인증 메커니즘을 지원할 수 있는데, 예를 들어 표준 사용자 이름과 비밀번호를 기반으로 한 인증, 토큰 기반 인증, 지문 인식 등을 처리할 수 있다.
                • 성공적인 인증 후에는 Authentication 객체를 반환하며 이 객체에는 사용자의 신원 정보와 인증된 자격 증명을 포함한다
                • 인증 과정 중에 문제가 발생한 경우 AuthenticationException 과 같은 예외를 발생시켜 문제를 알리는 역할을 한
         */
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(new CustomAuthenticationProvider());
        // http.authenticationProvider(new CustomAuthenticationProvider()); // 위의 코드와 동일한 처리를 한다.

        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
//                .authenticationProvider(new CustomAuthenticationProvider()) // authenticationManagerBuilder를 사용하지 않고 여기에 코드를 작성해도 된다.
        ;

        return http.build();
    }

    /**
     * AuthenticationProvider 사용 방법 - 빈으로 생성(하나의 빈으로 생성)
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManagerBuilder builder, AuthenticationConfiguration configuration) throws Exception {
//        // 자식 AuthenticationManagerBuilder 와 ProviderManager
//        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        managerBuilder.authenticationProvider(customAuthenticationProvider());
//
//        // 부모 AuthenticationManagerBuilder 와 ProviderManager
//        ProviderManager providerManager = (ProviderManager)configuration.getAuthenticationManager(); // 부모 parent
//        providerManager.getProviders().remove(0);
//        builder.authenticationProvider(new DaoAuthenticationProvider()); // 부모 빌더에 있는 부모 parent 에 추가한다.
//        // --> AuthenticationProvider 를 빈으로 정의하면 DaoAuthenticationProvder 를 자동으로 대체하게 된다
//
//        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }
//
//    @Bean
//    public AuthenticationProvider customAuthenticationProvider() {
//        return new CustomAuthenticationProvider();
//    }

    /**
     * AuthenticationProvider 사용 방법 - 빈으로 생성(2개 이상의 빈으로 생성)
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        managerBuilder.authenticationProvider(customAuthenticationProvider());
//        managerBuilder.authenticationProvider(customAuthenticationProvider2());
//
//        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
//        http.formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }
//
//    @Bean
//    public AuthenticationProvider customAuthenticationProvider() {
//        return new CustomAuthenticationProvider();
//    }
//
//    @Bean
//    public AuthenticationProvider customAuthenticationProvider2() {
//        return new CustomAuthenticationProvider2();
//    }

    @Bean
    public UserDetailsService userDetailsService() { // 해당 설정은 yml에서도 가능. 우선순위는 자바 설정이 더 높음.
        UserDetails user = User.withUsername("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails user2 = User.withUsername("user2")
                .password("{noop}2222")
                .roles("USER")
                .build();

        UserDetails user3 = User.withUsername("user3")
                .password("{noop}3333")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user, user2, user3);
    }

}
