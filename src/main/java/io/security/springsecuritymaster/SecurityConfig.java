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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            로그아웃
            • 스프링 시큐리티는 기본적으로 DefaultLogoutPageGeneratingFilter 를 통해 로그아웃 페이지를 제공하며 “ GET / logout ” URL 로 접근이 가능하다.
            • 로그아웃 실행은 기본적으로 “ POST / logout “ 으로만 가능하나 CSRF 기능을 비활성화 할 경우 혹은 RequestMatcher 를 사용할 경우 GET, PUT, DELETE 모두 가능하다
            • 로그아웃 필터를 거치지 않고 스프링 MVC 에서 커스텀 하게 구현할 수 있으며 로그인 페이지가 커스텀하게 생성될 경우 로그아웃 기능도 커스텀하게 구현해야 한다
         */
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/logoutSuccess").permitAll()
                        .anyRequest()
                        .authenticated())
                .formLogin(Customizer.withDefaults())
                .logout(httpSecurityLogoutConfigurer -> httpSecurityLogoutConfigurer
                        .logoutUrl("/logoutProc") // 로그아웃이 발생하는 URL 을 지정한다. (기본값은 “/logout” 이다)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc", "GET")) // 로그아웃이 발생하는 RequestMatcher 을 지정한다. logoutUrl 보다 우선적이다.
                                                                                                            // Method 를 지정하지 않으면logout URL이 어떤 HTTP 메서드로든 요청될 때 로그아웃 할 수 있다.
                        .logoutSuccessUrl("/logoutSuccess") // 로그아웃이 발생한 후 리다이렉션 될 URL이다. 기본값은 ＂/login?logout＂이다.
                        .logoutSuccessHandler((request, response, authentication) -> { // 사용할 LogoutSuccessHandler 를 설정합니다.
                            response.sendRedirect("/logoutSuccess"); // 이것이 지정되면 logoutSuccessUrl(String)은 무시된다.
                        })
                        .deleteCookies("CUSTOM_COOKIE") // 로그아웃 성공 시 제거될 쿠키의 이름을 지정할 수 있다.
                        .invalidateHttpSession(true) // HttpSession을 무효화해야 하는 경우 true(기본값), 그렇지 않으면 false 이다.
                        .clearAuthentication(true) // 로그아웃 시 SecurityContextLogoutHandler가 인증(Authentication)을 삭제 해야 하는지 여부를 명시한다. 기본값은 true.
                        .addLogoutHandler((request, response, authentication) -> {
                            // 기존의 로그아웃 핸들러 뒤에 새로운 LogoutHandler를 추가 한다.
                        })
                        .permitAll() // logoutUrl(), RequestMatcher() 의 URL 에 대한 모든 사용자의 접근을 허용 함.
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
