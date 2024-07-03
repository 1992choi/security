package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
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
            - SessionCreationPolicy
              • 스프링 시큐리티에서는 인증된 사용자에 대한 세션 생성 정책을 설정하여 어떻게 세션을 관리할지 결정할 수 있으며 이 정책은 SessionCreationPolicy 로 설정된다.

            - 세션 생성 정책 전략
              1. SessionCreationPolicy.ALWAYS
                 • 인증 여부에 상관없이 항상 세션을 생성한다.
                 • ForceEagerSessionCreationFilter 클래스를 추가 구성하고 세션을 강제로 생성시킨다.
              2. SessionCreationPolicy.NEVER
                 • 스프링 시큐리티가 세션을 생성하지 않지만 애플리케이션이 이미 생성한 세션은 사용할 수 있다.
              3. SessionCreationPolicy.IF_REQUIRED (기본값)
                 • 필요한 경우에만 세션을 생성한다. 예를 들어 인증이 필요한 자원에 접근할 때 세션을 생성한다.
              4. SessionCreationPolicy.STATELESS
                 • 세션을 전혀 생성하거나 사용하지 않는다.
                 • 인증 필터는 인증 완료 후 SecurityContext 를 세션에 저장하지 않으며 JWT 와 같이 세션을 사용하지 않는 방식으로 인증을 관리할 때 유용할 수 있다.
                 • SecurityContextHolderFilter 는 세션 단위가 아닌 요청 단위로 항상 새로운 SecurityContext 객체를 생성하므로 컨텍스트 영속성이 유지되지 않는다.
                 • STATELESS 설정에도 세션이 생성될 수 있다.
                   스프링 시큐리티에서 CSRF 기능이 활성화 되어 있고 CSRF 기능이 수행 될 경우 사용자의 세션을 생성해서 CSRF 토큰을 저장하게 된다.
                   세션은 생성되지만 CSRF 기능을 위해서 사용될 뿐 인증 프로세스의 SecurityContext 영속성에 영향을 미치지는 않는다.
         */
        http.authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
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
