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
        - AOP 메서드 보안 구현
          • MethodInterceptor, Pointcut, Advisor, AuthorizationManager 등을 커스텀하게 생성하여 AOP 메서드 보안을 구현 할 수 있다

        - AOP 요소
          • Advisor
            • AOP Advice 와 Advice 적용 가능성을 결정하는 포인트컷를 가진 기본 인터페이스이다
          • MethodInterceptor(Advice)
            • 대상 객체를 호출하기 전과 후에 추가 작업을 수행하기 위한 인터페이스로서 수행 이후 실제 대상 객체의 조인포인트 호출(메서드 호출)을 위해 Joinpoint.proceed()를 호출한다
          • Pointcut
            • AOP 에서 Advice 가 적용될 메소드나 클래스를 정의하는 것으로서 어드바이스가 실행되어야 하는 '적용 지점'이나 '조건'을 지정한다
            • ClassFilter 와 MethodMatcher 를 사용해서 어떤 클래스 및 어떤 메서드에 Advice 를 적용할 것인지 결정한다

        - AOP 적용 순서
          ① CustomMethodInterceptor 를 생성하고 메소드 보안 검사를 수행할 AuthorizationManager 를 CustomMethodInterceptor 에 전달한다
          ② CustomPointcut 을 생성하고 프록시 대상 클래스와 대상 메서드를 결정할 수 있도록 포인트컷 표현식을 정의한다
          ③ DefaultPointcutAdvisor 을 생성하고 CustomMethodInterceptor 와 CustomPointcut 을 DefaultPointcutAdvisor 에 전달한다
          ④ 서비스를 호출하면 Pointcut 으로부터 대상 클래스와 대상 메서드에 등록된 MethodInterceptor 를 탐색하고 결정되면 이를 호출하여 AOP 를 수행한다
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll())
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
