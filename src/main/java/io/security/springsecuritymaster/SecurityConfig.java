package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /*
        - 메서드 기반 Custom AuthorizationManager
          • 사용자 정의 AuthorizationManager 를 생성함으로 메서드 보안을 구현할 수 있다
          • @EnableMethodSecurity(prePostEnabled = false) // 시큐리티가 제공하는 클래스들을 비활성화 한다.
            그렇지 않으면 중복해서 검사하게 된다.
            (MethodSecurityConfig.java에 설정되어있음)

        - 인터셉터 순서 지정
          • AuthorizationInterceptorsOrder 를 사용하여 인터셉터 간 순서를 지정할 수 있다
          • 메서드 보안 어노테이션에 대응하는 AOP 메소드 인터셉터들은 AOP 어드바이저 체인에서 특정 위치를 차지한다
          • 구체적으로 @PreFilter 메소드 인터셉터의 순서는 100, @PreAuthorize의 순서는 200 등으로 설정되어 있다. (* 낮을수록 우선순위 높음)
          • 이것이 중요한 이유는 @EnableTransactionManagement와 같은 다른 AOP 기반 어노테이션들이 Integer.MAX_VALUE 로 순서가 설정되어 있는데
            기본적으로 이들은 어드바이저 체인의 끝에 위치하고 있다
          • 만약 스프링 시큐리티보다 먼저 다른 어드바이스가 실행 되어야 할 경우, 예를 들어 @Transactional 과 @PostAuthorize 가 함께 어노테이션 된 메소드가 있을 때
            @PostAuthorize가 실행될 때 트랜잭션이 여전히 열려있어서 AccessDeniedException 이 발생하면 롤백이 일어나게 하고 싶을 수 있다
          • 그래서 메소드 인가 어드바이스가 실행되기 전에 트랜잭션을 열기 위해서는 @EnableTransactionManagement 의 순서를 설정해야 한다
          • @EnableTransactionManagement(order = 0)
          • 위의 order = 0 설정은 트랜잭션 관리가 @PreFilter 이전에 실행되도록 하며
            @Transactional 어노테이션이 적용된 메소드가 스프링 시큐리티의 @PostAuthorize 와 같은 보안 어노테이션보다 먼저 실행되어 트랜잭션이 열린 상태에서 보안검사가 이루어지도록 할 수 있다.
            이러한 설정은 트랜잭션 관리와 보안 검사의 순서에 따른 의도하지 않은 사이드 이펙트를방지할 수 있다

     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
