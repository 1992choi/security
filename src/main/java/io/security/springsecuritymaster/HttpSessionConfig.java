package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.concurrent.ConcurrentHashMap;

@Configuration
@EnableSpringHttpSession
public class HttpSessionConfig {

    /*
        - SameSite
          • SameSite 는 최신 방식의 CSRF 공격 방어 방법 중 하나로서 서버가 쿠키를 설정할 때 SameSite 속성을 지정하여 크로스 사이트 간 쿠키 전송에 대한 제어를 핸들링 할 수 있다
          • Spring Security는 세션 쿠키의 생성을 직접 제어하지 않기 때문에 SameSite 속성에 대한 지원을 제공하지 않지만 Spring Session 은 SameSite 속성을 지원한다

        - SameSite 속성 종류
          1. Strict
             • 동일 사이트에서 오는 모든 요청에 쿠키가 포함되고 크로스 사이트간 HTTP 요청에 쿠키가 포함되지 않는다
          2. Lax(기본 설정)
             • 동일 사이트에서 오거나 Top Level Navigation 에서 오는 요청 및 메소드가 읽기 전용인 경우 쿠키가 전송되고 그렇지 않으면 HTTP 요청에 쿠키가 포함되지 않는다
             • 사용자가 링크(<a>)를 클릭하거나 window.location.replace , 302 리다이렉트 등의 이동이 포함된다. 그러나 <iframe>이나 <img>를 문서에 삽입, AJAX 통신 등은 쿠기가 전송되지 않는다
          3. None
             • 동일 사이트 및 크로스 사이트 요청의 경우에도 쿠키가 전송된다. 이 모드에서는 HTTS 의한 Secure 쿠키로 설정되야 한다
     */

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setUseSecureCookie(true);
        serializer.setUseHttpOnlyCookie(true);
        serializer.setSameSite("None");
        return serializer;
    }

    @Bean
    public SessionRepository<MapSession> sessionRepository() {
        return new MapSessionRepository(new ConcurrentHashMap<>());
    }

}
