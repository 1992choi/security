package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            RequestCache
            • 인증 절차 문제로 리다이렉트 된 후에 이전에 했던 요청 정보를 담고 있는 'SavedRequest’ 객체를 쿠키 혹은 세션에 저장하고 필요시 다시 가져와 실행하는 캐시 메카니즘이다

            SavedRequest
            • SavedRequest 은 로그인과 같은 인증 절차 후 사용자를 인증 이전의 원래 페이지로 안내하며 이전 요청과 관련된 여러 정보를 저장한다

            requestCache() API
            • 요청 Url 에 customParam=y 라는 이름의 매개 변수가 있는 경우에만 HttpSession 에 저장된 SavedRequest 을 꺼내오도록 설정할 수 있다 (기본값은 "continue" 이다)
            • 요청을 저장하지 않도록하려면 NullRequestCache 구현을 사용할 수 있다

            RequestCacheAwareFilter
            • RequestCacheAwareFilter 는 이전에 저장했던 웹 요청을 다시 불러오는 역할을 한다
            • SavedRequest 가 현재 Request 와 일치하면 이 요청을 필터 체인의 doFilter 메소드에 전달하고 SavedRequest 가 없으면 필터는 원래 Request 을 그대로 진행시킨다
         */
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setMatchingRequestParameterName("customParam=y"); // 기본값은 "continue". HttpSession에 저장된 SavedRequest를 꺼내오기 위함. 매번 가져올 필요가 없을수도 있기에 처리 구분을 위한 파라미터 값.
        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .successHandler((request, response, authentication) -> {
                            SavedRequest savedRequest = requestCache.getRequest(request, response);
                            String redirectUrl = savedRequest.getRedirectUrl();
                            response.sendRedirect(redirectUrl);
                        }))
                .requestCache(cache -> cache.requestCache(requestCache));

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
