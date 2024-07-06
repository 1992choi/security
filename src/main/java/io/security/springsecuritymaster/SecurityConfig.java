package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        /*
            - 요청 기반 권한 부여 : HttpSecurity.authorizeHttpRequests()
              • authorizeHttpRequests()는 사용자의 자원접근을 위한 요청 엔드포인트와 접근에 필요한 권한을 매핑시키기 위한 규칙을 설정하는 것으로서
                서블릿 기반 엔드포인트에 접근하려면 authorizeHttpRequests() 에 해당 규칙들을 포함해야 한다.
              • authorizeHttpRequests()를 통해 요청과 권한 규칙이 설정되면 내부적으로 AuthorizationFilter 가 요청에 대한 권한 검사 및 승인 작업을 수행한다.

            - requestMatchers()
              • requestMatchers 메소드는 HTTP 요청의 URL 패턴, HTTP 메소드, 요청 파라미터 등을 기반으로 어떤 요청에 대해서는 특정 보안 설정을 적용하고 다른 요청에 대해서는 적용하지 않도록 세밀하게 제어할 수 있게 해 준다
              • 예를 들어 특정 API 경로에만 CSRF 보호를 적용하거나, 특정 경로에 대해 인증을 요구하지 않도록 설정할 수 있다. 이를 통해 애플리케이션의 보안 요구 사항에 맞춰서 유연한 보안 정책을 구성할 수 있다
              • Ex) 1. requestMatchers(String... urlPatterns)
                       • 보호가 필요한 자원 경로를 한 개 이상 정의한다
                    2. requestMatchers(RequestMatcher... requestMatchers)
                       • 보호가 필요한 자원 경로를 한 개 이상 정의한다. AntPathRequestMatcher, MvcRequestMatcher 등의 구현체를 사용할 수 있다
                    3. requestMatchers(HttpMethod method, String... utlPatterns)
                       • Http Method 와 보호가 필요한 자원 경로를 한 개 이상 정의한다

            - 주의사항
              • 스프링 시큐리티는 클라이언트의 요청에 대하여 위에서 부터 아래로 나열된 순서대로 처리하며 요청에 대하여 첫 번째 일치만 적용되고 다음 순서로 넘어가지 않는다
              • /admin/** 가 /admin/db 요청을 포함하므로 의도한 대로 권한 규칙이 올바르게 적용 되지 않을 수 있다. 그렇기 때문에 엔드 포인트 설정 시 좁은 범위의 경로를 먼저 정의하고 그것 보다 큰 범위의 경로를 다음 설정으로 정의 해야 한다

            - 권한 규칙 종류
              • authenticated : 인증된 사용자의 접근을 허용한다
              • fullyAuthenticated : 아이디와 패스워드로 인증된 사용자의 접근을 허용, rememberMe 인증 제외한다
              • anonymous : 익명사용자의 접근을 허용한다
              • rememberMe : 기억하기를 통해 인증된 사용자의 접근을 허용한다
              • permitAll : 요청에 승인이 필요하지 않는 공개 엔드포인트이며 세션에서 Authentication 을 검색하지 않는다
              • denyAll : 요청은 어떠한 경우에도 허용되지 않으며 세션에서 Authentication 을 검색하지 않는다
              • access : 요청이 사용자 정의 AuthorizationManager 를 사용하여 액세스를 결정한다(표현식 문법 사용)
              • hasAuthority : 사용자의 Authentication 에는 지정된 권한과 일치하는 GrantedAuthority 가 있어야 한다
              • hasRole : hasAuthority 의 단축키로 ROLE_ 또는 기본접두사로 구성된다. ROLE_ 을 제외해야 한다
              • hasAnyAuthority : 사용자의 Authentication 에는 지정된 권한 중 하나와 일치하는 GrantedAuthority 가 있어야 한다
              • hasAnyRole : hasAnyAuthority의 단축키로 ROLE_ 또는 기본 접두사로 구성된다. ROLE_ 을 제외해야 한다
         */

        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/login").permitAll()
                        .requestMatchers("/user").hasAuthority("ROLE_USER") // "/user" 엔드포인트에 대해 "USER" 권한을 요구합니다.
                        .requestMatchers("/myPage/**").hasRole("USER") // "/mypage" 및 하위 디렉터리에 대해 "USER" 권한을 요구합니다. Ant 패턴 사용.
                        .requestMatchers(HttpMethod.POST).hasAuthority("ROLE_WRITE") // POST 메소드를 사용하는 모든 요청에 대해 "write" 권한을 요구합니다.
                        .requestMatchers(new AntPathRequestMatcher("/manager/**")).hasAuthority("ROLE_MANAGER") // "/manager" 및 하위 디렉터리에 대해 "MANAGER" 권한을 요구합니다. AntPathRequestMatcher 사용.
                        .requestMatchers(new MvcRequestMatcher(introspector, "/admin/payment")).hasAuthority("ROLE_ADMIN") // "/admin/payment" 및 하위 디렉터리에 대해 "ADMIN" 권한을 요구합니다. AntPathRequestMatcher 사용.
                        .requestMatchers("/admin/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MANAGER") // "/admin" 및 하위 디렉터리에 대해 "ADMIN" 또는 "MANAGER" 권한 중 하나를 요구합니다.
                        .requestMatchers(new RegexRequestMatcher("/resource/[A-Za-z0-9]+", null)).hasAuthority("ROLE_MANAGER") // 정규 표현식을 사용하여 "/resource/[A-Za-z0-9]+" 패턴에 "MANAGER" 권한을 요구합니다.
                        .anyRequest().authenticated())// 위에서 정의한 규칙 외의 모든 요청은 인증을 필요로 합니다.
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() { // 해당 설정은 yml에서도 가능. 우선순위는 자바 설정이 더 높음.
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails manager = User.withUsername("manager").password("{noop}1111").roles("MANAGER").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "WRITE").build();

        return new InMemoryUserDetailsManager(user, manager, admin);
    }

}
