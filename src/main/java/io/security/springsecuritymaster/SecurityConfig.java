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
            - CSRF(Cross Site Request Forgery, 사이트 간 요청 위조)
              • 웹 애플리케이션의 보안 취약점으로 공격자가 사용자로 하여금 이미 인증된 다른 사이트에 대해 원치 않는 작업을 수행하게 만드는 기법을 말한다.
              • 이 공격은 사용자의 브라우저가 자동으로 보낼 수 있는 인증 정보, 예를 들어 쿠키나 기본 인증 세션을 이용하여 사용자가 의도하지 않은 요청을 서버로 전송하게 만든다.
              • 이는 사용자가 로그인한 상태에서 악의적인 웹사이트를 방문하거나 이메일 등을 통해 악의적인 링크를 클릭할 때 발생할 수 있다.

            - CSRF 기능 활성화
              • 별도 설정을 하지 않아도 기본으로는 활성화 되어있다.
              • 토큰은 서버에 의해 생성되어 클라이언트의 세션에 저장되고 폼을 통해 서버로 전송되는 모든 변경 요청에 포함되어야 하며 서버는 이 토큰을 검증하여 요청의 유효성을 확인한다.
              • 기본 설정은 'GET', 'HEAD', 'TRACE', 'OPTIONS’ 와 같은 안전한 메서드를 무시하고 'POST', 'PUT', 'DELETE’ 와 같은 변경 요청 메서드에 대해서만 CSRF 토큰 검사를 수행한다.
              • 중요한 점은 실제 CSRF 토큰이 브라우저에 의해 자동으로 포함되지 않는 요청 부분에 위치해야 한다는 것으로서 HTTP 매개변수나 헤더에 실제 CSRF 토큰을 요구하는 것이 CSRF 공격을 방지하는데 효과적이라 할 수 있다.
              • 반면에 쿠키에 토큰을 요구하는 것은 브라우저가 쿠키를 자동으로 요청에 포함시키기 때문에 효과적이지 않다고 볼 수 있다.
         */

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/csrf").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
                //.csrf(csrf -> csrf.ignoringRequestMatchers("/csrf"));
                // 전체 비활성화 방법 = http.csrf(csrf -> disabled());
                // 일부 비활성화 방법 = http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/*"));

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
