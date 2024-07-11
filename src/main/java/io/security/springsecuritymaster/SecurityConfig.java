package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /*
        - Spring MVC 비동기 통합
          • Spring Security 는 Spring MVC Controller 에서 Callable 을 실행하는 비동기 스레드에 SecurityContext 를 자동으로 설정하도록 지원한다
          • Spring Security 는 WebAsyncManager 와 통합하여 SecurityContextHolder 에서 사용 가능한 SecurityContext 를 Callable 에서 접근 가능하도록 해 준다

        - WebAsyncManagerIntegrationFilter
          • SecurityContext 와 WebAsyncManager 사이의 통합을 제공하며 WebAsyncManager 를 생성하고
            SecurityContextCallableProcessingInterceptor를 WebAsyncManager 에 등록한다

        - WebAsyncManager
          • 스레드 풀의 비동기 스레드를 생성하고 Callable 를 받아 실행시키는 주체로서 등록된 SecurityContextCallableProcessingInterceptor 를 통해
            현재 스레드가 보유하고 있는 SecurityContext 객체를 비동기 스레드의 ThreadLocal 에 저장시킨다

        - 코드 구현
          • 비동기 스레드가 수행하는 Callable 영역 내에서 자신의 ThreadLocal 에 저장된 SecurityContext 를 참조할 수 있으며 이는 부모 스레드가 가지고 있는 SecurityContext 와 동일한 객체이다
          • @Async 나 다른 비동기 기술은 스프링 시큐리티와 통합되어 있지 않기 때문에 비동기 스레드에 SecurityContext 가 적용되지 않는다
          • Ex)
                @GetMapping("/callble")
                public Callable<Authentication> processUpload() {
                    // Main Thread 영역
                    SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
                    System.out.println("securityContext = " + securityContext);

                    return new Callable<Authentication>() {
                        // 비동기 Thread 영역
                        public Authentication call() throws Exception {
                            SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
                            System.out.println("securityContext = " + securityContext);
                            Authentication authentication = securityContext.getAuthentication();

                            return authentication;
                        }
                    }
                }
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/db").hasAuthority("ROLE_DB")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        // 해당 옵션을 키면 비동기 쓰레드 모드(=@Async)에서도 SecurityContext 공유가 가능하다.
        // SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

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