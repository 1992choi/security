package io.security.springsecuritymaster;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
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
        - Authorization Events
          • Spring Security 는 권한 부여 이벤트 처리를 지원하며 권한이 부여되거나 거부된 경우에 발생하는 이벤트를 수신할 수 있다
          • 이벤트를 수신하려면 ApplicationEventPublisher 를 사용하거나 시큐리티에서 제공하는 AuthorizationEventPublisher 를 사용해서 발행해야 한다
          • AuthorizationEventPublisher 의 구현체로 SpringAuthorizationEventPublisher 가 제공 된다
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/db").hasAuthority("ROLE_DB")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    // 인가 이벤트를 발행 하기 위해서는 SpringAuthorizationEventPublisher 를 빈으로 정의해야 한다
//    @Bean
//    public AuthorizationEventPublisher authorizationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
//        return new SpringAuthorizationEventPublisher(applicationEventPublisher);
//    }

    // 커스텀 AuthorizationEventPublisher
    @Bean
    public AuthorizationEventPublisher myAuthorizationEventPublisher(ApplicationEventPublisher applicationEventPublisher){
        return new MyAuthorizationEventPublisher(new SpringAuthorizationEventPublisher(applicationEventPublisher), applicationEventPublisher);
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails db = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN","SECURE").build();
        return  new InMemoryUserDetailsManager(user, db, admin);
    }

}
