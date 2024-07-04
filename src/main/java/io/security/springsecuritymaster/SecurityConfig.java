package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        /*
            - CORS(Cross Origin Resource Sharing, 교차 출처 리소스 공유)
              • 웹에서는 보안을 위해 기본적으로 한 웹 페이지(출처 A)에서 다른 웹 페이지(출처 B)의 데이터를 직접 불러오는 것을 제한하는데 이를 '동일 출처 정책(Same-Origin Policy)' 이라고 한다.
              • CORS는 특별한 HTTP 헤더를 통해 한 웹 페이지가 다른 출처의 리소스에 접근할 수 있도록 '허가'를 구하는 방법이다.
              • '동일 출처'를 비교하는 방법은 URL의 구성요소 중 Protocol, Host, Port이 3개가 모두 일치하는지 판단한다.

            - CORS 종류
              1. Simple Request
                 • Simple Request 는 예비 요청(Prefilght) 과정 없이 자동으로 CORS 가 작동하여 서버에 본 요청을 한 후, 서버가 응답의 헤더에 Access-Control-Allow-Origin 과 같은 값을 전송하면 브라우저가 서로 비교 후 CORS 정책 위반여부를 검사하는 방식이다.
                 • 제약사항 (아래를 모두 만족하지 못하면 Preflight Request을 사용하게 된다.)
                   - GET, POST, HEAD 중의 한가지 Method를 사용해야 한다
                   - 헤더는 Accept, Accept-Language, Content-Language, Content-Type, DPR, Downlink, Save-Data, Viewport-Width Width 만 가능하고 Custom Header 는 허용되지 않는다
                   - Content-type 은 application/x-www-form-urlencoded, multipart/form-data, text/plain 만 가능하다

              2. Preflight Request (예비요청)
                 • 브라우저는 요청을 한번에 보내지 않고, 예비 요청과 본 요청으로 나누어 서버에 전달하는데 브라우저가 예비요청을 보내는 것을 Preflight라고 하며, 이 예비요청의 메소드에는 OPTIONS가 사용된다
                 • 예비요청의 역할은 본 요청을 보내기 전에 브라우저 스스로 안전한 요청인지 확인하는 것으로, 요청 사양이 Simple Request에 해당하지 않을 경우 브라우저가 Preflight Request을 실행한다

            - CORS 해결방법 (서버에서 Access-Control-Allow-* 세팅)
                • Access-Control-Allow-Origin
                    : 설정된 출처만 브라우저가 리소스를 접근할 수 있도록 허용한다
                    : *, https://security.io
                • Access-Control-Allow-Methods
                    : preflight request 에 대한 응답으로 실제 요청 중에 사용할 수 있는 메서드를 나타낸다
                    : 기본값은 GET, POST, HEAD, OPTIONS, *
                • Access-Control-Allow-Headers
                    : preflight request 에 대한 응답으로 실제 요청 중에 사용할 수 있는 헤더 필드 이름을 나타낸다
                    : 기본값은 Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, Custom Header, *
                • Access-Control-Allow-Credentials
                    : 실제 요청에 쿠기나 인증 등의 사용자 자격 증명이 포함될 수 있음을 나타낸다. Client의 credentials:include 옵션일 경우 true는 필수
                • Access-Control-Max-Age
                    : preflight 요청 결과를 캐시 할 수 있는 시간을 나타내는 것으로 해당 시간동안은 preflight 요청을 다시 하지 않게 된다
         */

        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("http://localhost:8080");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(1L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

}
