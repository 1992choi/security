package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - UserDetailsService
              • UserDetailsService의 주요 기능은 사용자와 관련된 상세 데이터를 로드하는 것이며 사용자의 신원, 권한, 자격 증명 등과 같은 정보를 포함할 수 있다
              • 이 인터페이를 사용하는 클래스는 주로 AuthenticationProvider 이며 사용자가 시스템에 존재하는지 여부와 사용자 데이터를 검색하고 인증 과정을 수행한다

            - UserDetailsService 사용 방법
              • UserDetailsService 만 커스트 마이징 할 경우 위와 같이 적용하면 된다
              • AuthenticationProvider 와 함께 커스트 마이징 할 경우 AuthenticationProvider 에 직접 주입해서 사용한다
         */

        // UserDetailsService를 Bean으로 등록할 경우, 아래 코드를 생략할 수 있다. 만약 Bean이 아니라 객체를 생성해서 쓸 경우는 아래 코드처럼 사용해야한다.
//        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        managerBuilder.userDetailsService(customUserDetailsService());
//        // http.userDetailsService(customUserDetailsService()); // 위의 코드와 동일하게 동작함.

        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public UserDetailsService customUserDetailsService() {
        return new CustomUserDetailsService();
    }

}
