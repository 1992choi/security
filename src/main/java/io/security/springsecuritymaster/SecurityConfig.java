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
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
@Configuration
public class SecurityConfig {

    /*
        - 메서드 기반 인가 관리자
          • 스프링 시큐리티는 메서드 기반의 인증된 사용자 및 특정권한을 가진 사용자의 자원접근 허용여부를 결정하는 인가 관리자 클래스들을 제공한다
          • PreAuthorizeAuthorizationManager, PostAuthorizeAuthorizationManager, Jsr250AuthorizationManager, SecuredAuthorizationManager 가 있다
          • 메서드 기반 권한 부여는 내부적으로 AOP 방식에 의해 초기화 설정이 이루어지며 메서드의 호출을 MethodInterceptor 가 가로 채어 처리하고 있다

        - 메서드 권한 부여 초기화 과정
          ① 스프링은 초기화 시 생성되는 전체 빈을 검사하면서 빈이 가진 메소드 중에서 보안이 설정된 메소드가 있는지 탐색한다
          ② 보안이 설정된 메소드가 있다면 스프링은 그 빈의 프록시 객체를 자동으로 생성한다 (기본적으로 Cglib 방식으로 생성한다)
          ③ 보안이 설정된 메소드에는 인가처리 기능을 하는 Advice 를 등록한다
          ④ 스프링은 빈 참조시 실제 빈이 아닌 프록시 빈 객체를 참조하도록 처리한다
          ⑤ 초기화 과정이 종료된다
          ⑥ 사용자는 프록시 객체를 통해 메소드를 호출하게 되고 프록시 객체는 Advice 가 등록된 메서드가 있다면 호출하여 작동 시킨다
          ⑦ Advice 는 메소드 진입 전 인가 처리를 하게 되고 인가처리가 승인되면 실제 객체의 메소드를 호출하게 되고 인가처리가 거부되면 예외가 발생하고 메소드 진입이 실패한다

        - 메서드 인터셉터 구조
          • AuthorizationManagerBeforeMethodInterceptor
            : 지정된 AuthorizationManager 를 사용하여 Authentication 이 보안 메서드를 호출 할 수 있는지 여부를 결정하는 MethodInterceptor 구현체이다
          • AuthorizationManagerAfterMethodInterceptor
            : 지정된 AuthorizationManager 를 사용하여 Authentication 이 보안 메서드의 반환 결과에 접근 할 수 있는지 여부를 결정할 수 있는 구현체이다
          • PreFilterAuthorizationMethodInterceptor
            : @PreFilter 어노테이션에서 표현식을 평가하여 메소드 인자를 필터링 하는 구현체이다
          • PostFilterAuthorizationMethodInterceptor
            : @PostFilter 어노테이션에서 표현식을 평가하여 보안 메서드에서 반환된 객체를 필터링 하는 구현체이다
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
