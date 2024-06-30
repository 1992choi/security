package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
            - HTTP Basic 인증
                : HTTP 는 액세스 제어와 인증을 위한 프레임워크를 제공하며 가장 일반적인 인증 방식은 "Basic" 인증 방식이다.
                : RFC 7235 표준이며 인증 프로토콜은 HTTP 인증 헤더에 기술되어 있다.
                : base-64 인코딩된 값은 디코딩이 가능하기 때문에 인증정보가 노출된다.
                : HTTP Basic 인증은 반드시 HTTPS와 같이 TLS 기술과 함께 사용해야 한다.

            - 인증절차
                1. 클라이언트는 인증정보 없이 서버로 접속을 시도한다.
                2. 서버가 클라이언트에게 인증요구를 보낼 때 401 Unauthorized 응답과 함께 WWW-Authenticate 헤더를 기술해서 realm(보안영역) 과 Basic 인증방법을 보냄.
                   - WWW-Authenticate를 강제로 오타를 발생시켜 잘못된 헤더를 기술(Ex. W-Authenticate)할 경우,
                     클라이언트에서는 인증 프롬프트가 활성화되지 않아 인증과정을 진행할 수 없다.
                3. 클라이언트가 서버로 접속할 때 Base64 로 username 과 password 를 인코딩하고 Authorization 헤더에 담아서 요청함.
                4. 성공적으로 완료되면 정상적인 상태 코드를 반환한다.
         */
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .httpBasic(basic -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));

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
