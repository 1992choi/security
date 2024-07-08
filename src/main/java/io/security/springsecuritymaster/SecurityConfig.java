package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /*
        - Authorization
          • 인가 즉 권한 부여는 특정 자원에 접근할 수 있는 사람을 결정하는 것을 의미한다
          • Spring Security 는 GrantedAuthority 클래스를 통해 권한 목록을 관리하고 있으며 사용자의 Authentication 객체와 연결한다

        - GrantedAuthority
          • 스프링 시큐리티는 Authentication 에 GrantedAuthority 권한 목록을 저장하며 이를 통해 인증 주체에게 부여된 권한을 사용하도록 한다
          • GrantedAuthority 객체는 AuthenticationManager 에 의해 Authentication 객체에 삽입되며 스프링 시큐리티는 인가 결정을 내릴 때,
            AuthorizatioinManager 를 사용하여 Authentication 즉, 인증 주체로부터 GrantedAuthority 객체를 읽어들여 처리하게 된다

        - 사용자 정의 역할 접두사
          • 기본적으로 역할 기반의 인가 규칙은 역할 앞에 ROLE_를 접두사로 사용한다.
            즉, "USER" 역할을 가진 보안 컨텍스트가 필요한 인가 규칙이 있다면 Spring Security 는 기본적으로 "ROLE_USER" 를 반환하는 GrantedAuthority#getAuthority 를 찾는다
          • GrantedAuthorityDefaults 로 사용자 지정할 수 있으며 GrantedAuthorityDefaults 는 역할 기반 인가 규칙에 사용할 접두사를 사용자 정의하는 데 사용된다.
          • Ex) @Bean
                static GrantedAuthorityDefaults grantedAuthorityDefaults() {
                    return new GrantedAuthorityDefaults("MYPREFIX_");
                }
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user").hasRole("USER")
                        .requestMatchers("/db").hasRole("DB")
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("MYPREFIX_");
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").authorities("MYPREFIX_USER").build(); // 접근 가능
        UserDetails db = User.withUsername("db").password("{noop}1111").roles("MYPREFIX_DB").build(); // Role Prefix 재정의하여 접근 불가
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "SECURE").build(); // Role Prefix 재정의하여 접근 불가
        return new InMemoryUserDetailsManager(user, db, admin);
    }

}
