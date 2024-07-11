package io.security.springsecuritymaster;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
        - @AuthenticationPrincipal
          • Spring Security는 Spring MVC 인수에 대한 현재 Authentication.getPrincipal()을 자동으로 해결 할 수 있는 AuthenticationPrincipalArgumentResolver 를 제공한다
          • Spring MVC 에서 @AuthenticationPrincipal 을 메서드 인수에 선언하게 되면 Spring Security 와 독립적으로 사용할 수 있다
          • 어노테이션을 활용하여 AuthenticationPrincipalArgumentResolver 에서 메서드 호출 전 가로 채어 인수값을 해결하고 전달할 수 있다.
            Ex)
                @RequestMapping("/user")
                public void findUser() {
                    Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
                    CustomUser custom = (CustomUser) authentication == null ? null : authentication.getPrincipal();
                }

                --> 아래와 같이 변경할 수 있다.

                @RequestMapping("/user")
                public Customer findUser(@AuthenticationPrincipal CustomUser customUser) {
                    // ...
                }

        - @AuthenticationPrincipal(expression="표현식")
          • Principal 객체 내부에서 특정 필드나 메서드에 접근하고자 할 때 사용할 수 있으며 사용자 세부 정보가 Principal 내부의 중첩된 객체에 있는 경우 유용하다
          • Ex)
                @RequestMapping("/user")
                public Customer findUser(@AuthenticationPrincipal(expression = "customer") Customer customer) {
                    // ...
                }


        - @AuthenticationPrincipal 메타 주석
          • @AuthenticationPrincipal 을 자체 주석으로 메타 주석화 하여 Spring Security 에 대한 종속성을 제거할 수도 있다
          • Ex)
                @Target({ ElementType.PARAMETER, ElementType.TYPE })
                @Retention(RetentionPolicy.RUNTIME)
                @Documented
                @AuthenticationPrincipal
                public @interface CurrentUser {
                }

                --> 사용

                @RequestMapping("/user")
                public void user(@CurrentUser CustomUser customUser) {
                    // ...
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