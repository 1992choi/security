package io.security.springsecuritymaster;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/anonymous")
    public String anonymous() {
        return "anonymous";
    }

    @GetMapping("/authentication")
    public String authentication(Authentication authentication) {
        // - 스프링 MVC 에서 익명 인증 사용하기 (잘못된 방식)
        //   : 요청이 익명일 때 이 값은 null이다.
        //     익명에 대한 분기를 아래와 같이 처리하면,
        //     익명인 경우 null이기 때문에 else를 타고, 정상 로그인을 해도 AnonymousAuthenticationToken이 아니기 때문에 else문을 탄다. (모두 else문을 타게되는 상황.)
        //     따라서 익명 요청에서 Authentication을 얻고 싶다면 아래 메서드(=anonymousContext)를 참고해서 처리해야한다.
        if (authentication instanceof AnonymousAuthenticationToken) {
            return "anonymous";
        } else {
            return "not anonymous";
        }
    }

    @GetMapping("/anonymousContext")
    public String anonymousContext(@CurrentSecurityContext SecurityContext securityContext) {
        // - 스프링 MVC 에서 익명 인증 사용하기 (올바른 방식)
        //   : 익명 요청에서 Authentication 을 얻고 싶다면 @CurrentSecurityContext를 사용하면 된다.
        //     CurrentSecurityContextArgumentResolver 에서 요청을 가로채어 처리한다.
        return securityContext.getAuthentication().getName();
    }

}
