package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - SecurityContextRepository
              • 스프링 시큐리티에서 사용자가 인증을 한 이후 요청에 대해 계속 사용자의 인증을 유지하기 위해 사용되는 클래스이다
              • 인증 상태의 영속 메커니즘은 사용자가 인증을 하게 되면 해당 사용자의 인증 정보와 권한이 SecurityContext에 저장되고 HttpSession 을 통해 요청 간 영속이 이루어 지는 방식이다

            - SecurityContextHolderFilter
              • SecurityContextRepository 를 사용하여 SecurityContext를 얻고 이를 SecurityContextHolder 에 설정하는 필터 클래스이다
              • 이 필터 클래스는 SecurityContextRepository.saveContext()를 강제로 실행시키지 않고 사용자가 명시적으로 호출되어야 SecurityContext를 저장할 수 있는데 이는 SecurityContextPersistenceFilter와 다른점이다.
                - SecurityContextPersistenceFilter는 이전 시큐리티 버전에서 사용된 필터로 Session에 SecurityContext를 항상 저장하도록 구현되어 있다. (SecurityContextHolderFilter는 저장을 강제하지 않는다.)
              • 인증이 지속되어야 하는지를 각 인증 메커니즘이 독립적으로 선택할 수 있게 하여 더 나은 유연성을 제공하고 HttpSession 에 필요할 때만 저장함으로써 성능을 향상시킨다
         */
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/login").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .securityContext(securityContext -> securityContext
                        .requireExplicitSave(false)) // 옵션에 따른 결과는 아래 주석 확인.
                                                     // 해당 옵션말고 직접 필터에서 구현할 수도 있다. (CustomAuthenticationFilter.java의 setSecurityContextRepository(getSecurityContextRepository(http)); 코드 참고.
                .authenticationManager(authenticationManager)
                .addFilterBefore(customFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class);
        /*
            - /api/login?username=user&password=1111를 호출할 때 동작.
                requireExplicitSave(false)가 아닌 경우(=true가 기본값), SecurityContextPersistanceFilter가 실행되기 때문에 인증된 결과가 저장되지 않아서 다시 로그인 화면으로 돌아간다.
                requireExplicitSave(true)인 경우, SecurityContextHolderFilter가 실행되기 때문에 정상적으로 로그인 후 인증된 결과가 세션에 저장되어 index 페이지로 정상 접근하는 것을 확인할 수 있다.
         */

        return http.build();
    }

    public CustomAuthenticationFilter customFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);

        return customAuthenticationFilter;
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
