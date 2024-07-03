package io.security.springsecuritymaster;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @PostMapping("/login") // login은 시큐리티에서 기본적으로 정의되어 있는 URI이기 때문에 기본 동작으 수행되지 않도록 조치가 필요하다.(Ex. securityConfig에서 .formLogin(Customizer.withDefaults()) 비활성화)
    public Authentication customLogin(@RequestBody LoginRequest login, HttpServletRequest request, HttpServletResponse response) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()); // 사용자 이름과 비밀번호를 담은 인증 객체를 생성한다
        Authentication authentication = authenticationManager.authenticate(token); // 인증을 시도하고 최종 인증 결과를 반환한다

        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication); // 인증 결과를 컨텍스트에 저장한다
        SecurityContextHolder.getContextHolderStrategy().setContext(securityContext); // 컨텍스트를 ThreadLocal에 저장한다

        securityContextRepository.saveContext(securityContext, request, response); // 컨텍스트를 세션에 저장해서 인증 상태를 영속한다

        return authentication;
    }

}