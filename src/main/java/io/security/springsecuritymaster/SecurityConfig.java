package io.security.springsecuritymaster;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    /*
        - 메서드 기반 권한 부여
          • Spring Security 는 요청 수준의 권한 부여뿐만 아니라 메서드 수준에서의 권한 부여를 지원한다
          • 메서드 수준 권한 부여를 활성화 하기 위해서는 설정 클래스에 @EnableMethodSecurity 어노테이션을 추가해야 한다
          • SpEL(Spring Expression Language) 표현식을 사용하여 다양한 보안 조건을 정의할 수 있다

        - @PreAuthorize
          • @PreAuthorize 어노테이션은 메소드가 실행되기 전에 특정한 보안 조건이 충족되는지 확인하는 데 사용되며,
            보통 서비스 또는 컨트롤러 레이어의 메소드에 적용되어 해당 메소드가 호출되기 전에 사용자의 인증 정보와 권한을 검사한다

        - @PostAuthorize
          • @PostAuthorize 어노테이션은 메소드가 실행된 후에 보안 검사를 수행하는 데 사용된다
          • @PreAuthorize 와는 달리, @PostAuthorize는 메소드 실행 후 결과에 대한 보안 조건을 검사하여 특정 조건을 만족하는 경우에만 사용자가 결과를 받을 수 있도록 한다
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

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
