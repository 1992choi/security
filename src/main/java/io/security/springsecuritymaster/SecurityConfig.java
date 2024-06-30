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
        /**
         * 강의에서 동작만 확인하기 위하여 화면단은 만들지 않고 진행되었음.
         */
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/loginPage") // 사용자 정의 로그인 페이지로 전환, 기본 로그인페이지 무시
                        .loginProcessingUrl("/loginProc") // 사용자 이름과 비밀번호를 검증할 URL 지정 (Form태그의 action과 동일한 값)
                        .defaultSuccessUrl("/", true) // 로그인 성공 이후 이동 페이지, alwaysUse가 true이면 무조건 지정된 위치로 이동(기본은 false). 인증 전에 보안이 필요한 페이지를 방문하다가 인증에 성공한 경우이면 이전 위치로 리다이렉트 됨.
                        .failureUrl("/failed") // 인증에 실패할 경우 사용자에게 보내질 URL 을 지정, 기본값은 "/login?error"이다
                        .usernameParameter("userId") // 인증을 수행할 때 사용자 이름(아이디)을 찾기 위해 확인하는 HTTP 매개변수 설정, 기본값은 username
                        .passwordParameter("passwd") // 인증을 수행할 때 비밀번호를 찾기 위해 확인하는 HTTP 매개변수 설정, 기본값은 password
                        .successHandler((request, response, authentication) -> { // 인증 성공 시 사용할 AuthenticationSuccessHandler를 지정. 기본값은 SavedRequestAwareAuthenticationSuccessHandler이다
                            System.out.println("authentication : " + authentication);
                            response.sendRedirect("/home");
                        })
                        .failureHandler((request, response, exception) -> { // 인증 실패 시 사용할 AuthenticationFailureHandler를 지정. 기본값은 SimpleUrlAuthenticationFailureHandler 를 사용하여 "/login?error"로 리다이렉션 함
                            System.out.println("exception : " + exception.getMessage());
                            response.sendRedirect("/login");
                        })
                        .permitAll() // failureUrl(), loginPage(), loginProcessingUrl() 에 대한 URL 에 모든 사용자의 접근을 허용 함
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
