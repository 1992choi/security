package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /**
     * AuthenticationManager 사용 방법 - HttpSecurity 사용
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - AuthenticationManager
                • 인증 필터로부터 Authentication 객체를 전달 받아 인증을 시도하며 인증에 성공할 경우 사용자 정보, 권한 등을 포함한 완전히 채워진 Authentication 객체를 반환한다
                • AuthenticationManager 는 여러 AuthenticationProvider 들을 관리하며 AuthenticationProvider 목록을 순차적으로 순회하며 인증 요청을 처리한다
                • AuthenticationProvider 목록 중에서 인증 처리 요건에 맞는 적절한 AuthenticationProvider 를 찾아 인증처리를 위임한다
                • AuthenticationManagerBuilder 에 의해 객체가 생성되며 주로 사용하는 구현체로 ProviderManager 가 제공된다

            - AuthenticationManagerBuilder
                • AuthenticationManager 객체를 생성하며 UserDetailsService 및 AuthenticationProvider 를 추가할 수 있다
                • HttpSecurity.getSharedObject(AuthenticationManagerBuilder.class) 를 통해 객체를 참조할 수 있다
         */
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build(); // build() 는 최초 한번 만 호출해야 한다
        // AuthenticationManager authenticationManager = authenticationManagerBuilder.getObject(); //build()후에는 getObject()로 참조해야 한다.

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/api/login").permitAll()
                        .anyRequest().authenticated())
                .authenticationManager(authenticationManager)
                .addFilterBefore(customFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    public CustomAuthenticationFilter customFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
        return customAuthenticationFilter;
    }

    /**
     * AuthenticationManager 사용 방법 - 직접 생성
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/", "/api/login").permitAll()
//                        .anyRequest().authenticated())
//                .addFilterBefore(customFilter(http), UsernamePasswordAuthenticationFilter.class);
//        return http.build();
//    }
//
//    public CustomAuthenticationFilter customFilter(HttpSecurity http) {
//        List<AuthenticationProvider> list1 = List.of(new DaoAuthenticationProvider());
//        ProviderManager parent = new ProviderManager(list1);
//        List<AuthenticationProvider> list2 = List.of(new AnonymousAuthenticationProvider("key"), new CustomAuthenticationProvider());
//        ProviderManager authenticationManager = new ProviderManager(list2, parent);
//
//        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
//        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
//
//        return customAuthenticationFilter;
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
