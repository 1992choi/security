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

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - @Secured
              • @Secured 어노테이션을 메소드에 적용하면 지정된 권한(역할)을 가진 사용자만 해당 메소드를 호출할 수 있으며 더 풍부한 형식을 지원하는 @PreAuthorize 사용을 권장한다
              • @Secured 어노테이션을 사용하려면 스프링 시큐리티 설정에서 @EnableMethodSecurity(securedEnabled = true) 설정을 활성화해야 한다

            - JSR-250
              • JSR-250 기능을 적용하면 @RolesAllowed, @PermitAll 및 @DenyAll 어노테이션 보안 기능이 활성화 된다
              • JSR-250 어노테이션을 사용하려면 스프링 시큐리티 설정에서 @EnableMethodSecurity(jsr250Enabled = true) 설정을 활성화해야 한다

            - 메타 주석 사용
              • 메서드 보안은 애플리케이션의 특정 사용을 위해 편리성과 가독성을 높일 수 있는 메타 주석을 지원한다
                Ex) 어노테이션을 통해 @PreAuthorize("hasRole('ADMIN')")를 @IsAdmin으로 간소화할 수 있다.

            - 커스텀 빈을 사용하여 표현식
              • 사용자 정의 빈을 생성하고 새로운 표현식으로 사용할 메서드를 정의하고 권한 검사 로직을 구현한다.
                Ex)
                    @GetMapping("/delete")
                    @PreAuthorize("@authorizer.isUser(#root)") //빈 이름을 참조하고 접근 제어 로직을 수행한다
                    public void delete(){
                        System.out.println("delete");
                    }

                    @Component("authorizer")
                    class MyAuthorizer {
                        public boolean isUser(MethodSecurityExpressionOperations root){
                            boolean decision = root.hasAuthority("ROLE_USER"); //인증된 사용자가 ROLE_USER권한을 가지고 있는지를 검사
                            return decision;
                        }
                    }

            - 클래스 레벨 권한 부여
              • 모든 메소드는 클래스 수준의 권한 처리 동작을 상속한다 (@Transaction 어노테이션과 비슷하게 동작)
              • 메서드에 어노테이션을 선언한 메소드는 클래스 수준의 어노테이션을 덮어쓰게 된다
              • 인터페이스에도 동일한 규칙이 적용되지만 클래스가 두 개의 다른 인터페이스로부터 동일한 메서드의 어노테이션을 상속받는 경우에는 시작할 때 실패한다.
                그래서 구체적인 메소드에 어노테이션을 추가함으로써 모호성을 해결할 수 있다.
         */

        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails db = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN","SECURE").build();
        return  new InMemoryUserDetailsManager(user, db, admin);
    }

}
