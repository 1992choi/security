package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - @PreFilter
              • @PreFilter 어노테이션은 메소드가 실행되기 전에 메소드에 전달된 컬렉션 타입의 파라미터에 대한 필터링을 수행하는데 사용된다
              • @PreFilter 어노테이션은 주로 사용자가 보내온 컬렉션(배열, 리스트, 맵, 스트림) 내의 객체들을 특정 기준에 따라 필터링하고
                그 중 보안 조건을 만족하는 객체들에 대해서만 메소드가 처리하도록 할 때 사용된다
                Ex) 필터 적용 전 데이터가 {A, B, C}일 때, 필터에 의해 조건을 만족하는 {A, B}만 반환.

            - @PostFilter
              • @PostFilter 어노테이션은 메소드가 반환하는 컬렉션 타입의 결과에 대해 필터링을 수행하는 데 사용된다
              • @PostFilter 어노테이션은 메소드가 컬렉션을 반환할 때 반환되는 각 객체가 특정 보안 조건을 충족하는지 확인하고 조건을 만족하지 않는 객체들을 결과에서 제거한다
         */

        http
                .authorizeHttpRequests(authorize -> authorize
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