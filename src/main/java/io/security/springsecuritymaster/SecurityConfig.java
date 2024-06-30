package io.security.springsecuritymaster;

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

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            익명 사용자
            • 스프링 시큐리티에서 "익명으로 인증된" 사용자와 인증되지 않은 사용자 간에 실제 개념적 차이는 없으며, 단지 액세스 제어 속성을 구성하는 더 편리한 방법을 제공한다고 볼 수 있다.
            • SecurityContextHolder가 항상 Authentication 객체를 포함하고 null을 포함하지 않는다는 것을 규칙을 세우게 되면 클래스를 더 견고하게 작성할 수 있다.
            • 인증 사용자와 익명 인증 사용자를 구분해서 어떤 기능을 수행하고자 할 때 유용할 수 있으며 익명 인증 객체를 세션에 저장하지 않는다.
            • 익명 인증 사용자의 권한을 별도로 운용할 수 있다. 즉 인증 된 사용자가 접근할 수 없도록 구성이 가능하다.
         */
        http.authorizeHttpRequests(auth ->
                        auth.requestMatchers("/anonymous").hasRole("GUEST")
                                .requestMatchers("/anonymousContext", "/authentication").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .anonymous(anonymous -> anonymous
                        .principal("guest")
                        .authorities("ROLE_GUEST")
                );

        return http.build();
    }

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
