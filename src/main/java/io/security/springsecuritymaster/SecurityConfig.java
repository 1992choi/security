package io.security.springsecuritymaster;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /*
        - Custom DSLs
          • Spring Security 는 사용자 정의 DSL 을 구현할 수 있도록 지원한다
          • DSL 을 구성하면 필터, 핸들러, 메서드, 속성 등을 한 곳에 정의하여 처리할 수 있는 편리함을 제공한다

        - AbstractHttpConfigurer<AbstractHttpConfigurer, HttpSecurityBuilder>
          • 사용자 DSL 을 구현하기 위해서 상속받는 추상 클래스로서 구현 클래스는 두 개의 메서드를 오버라이딩 한다
            • init(B builder) - HttpSecurity 의 구성요소를 설정 및 공유하는 작업 등..
            • configure(B builder) - 공통클래스를 구성 하거나 사용자 정의 필터를 생성하는 작업 등..

        - API
          • HttpSecurity.with(C configurer, Customizer<C> customizer)
            • configurer 는 AbstractHttpConfigurer 을 상속하고 DSL 을 구현한 클래스가 들어간다
            • customizer 는 DSL 구현 클래스에서 정의한 여러 API 를 커스트 마이징한다
            • 동일한 클래스를 여러 번 설정하더라도 한번 만 적용 된다
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {
        /*
            DSL을 통해 커스텀 필터를 등록한 예제.
            - DSL 을 구성하면 필터, 핸들러, 메서드, 속성 등을 한 곳에 정의하여 처리할 수 있는 편리함을 제공한다.
            - 예제에서는 필터에 true 값을 주면, 자동으로 user로 로그인한 효과가 나타난다.
              --> 실무에서는 맞지 않는 예제이지만, 이와같이 커스텀 로직을 추가할 수 있다. (이전 학습과 같이 옵션을 통해 추가할 수도 있지만 한 곳에 정의할 수 있다는 장점이 있음)
         */
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/db").hasAuthority("ROLE_DB")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .with(MyCustomDsl.customDsl(), dsl -> dsl.flag(true));

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