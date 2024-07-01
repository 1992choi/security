package io.security.springsecuritymaster;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityContextService {

    public void securityContext() {
        /*
            - SecurityContext 특징
            Authentication 저장 : 현재 인증된 사용자의 Authentication 객체를 저장한다
            ThreadLocal 저장소 사용 : SecurityContextHolder 를 통해 접근되며 ThreadLocal 저장소를 사용해 각 스레드가 자신만의 보안 컨텍스트를 유지한다
            애플리케이션 전반에 걸친 접근성 : 애플리케이션의 어느 곳에서나 접근 가능하며 현재 사용자의 인증 상태나 권한을 확인하는 데 사용된다

            - SecurityContextHolder 특징
            SecurityContext 저장 : 현재 인증된 사용자의 Authentication 객체를 담고 있는 SecurityContext 객체를 저장한다
            전략 패턴 사용 : 다양한 저장 전략을 지원하기 위해 SecurityContextHolderStrategy 인터페이스를 사용한다
            기본 전략 : MODE_THREADLOCAL
            전략 모드 직접 지정 : SecurityContextHolder.setStrategyName(String)

            - SecurityContextHolder 저장 모드
            MODE_THREADLOCAL : 기본 모드로, 각 스레드가 독립적인 보안 컨텍스트를 가집니다. 대부분의 서버 환경에 적합하다
            MODE_INHERITABLETHREADLOCAL : 부모 스레드로부터 자식 스레드로 보안 컨텍스트가 상속되며 작업을 스레드 간 분산 실행하는 경우 유용 할 수 있다
            MODE_GLOBAL : 전역적으로 단일 보안 컨텍스트를 사용하며 서버 환경에서는 부적합하며 주로 간단한 애플리케이션에 적합하다
         */

        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext(); // 기존에는 'SecurityContext context = SecurityContextHolder.createEmptyContext();' 형태로 사용되었다.
                                                                                                         // 이렇게 코드를 작성할 경우, SecurityContextHolder 를 통해 SecurityContext 에 정적으로 접근할 때 여러 애플리케이션 컨텍스트가 SecurityContextHolderStrategy를 지정하려고 할 때 경쟁 조건을 만들 수 있다.
        Authentication authentication = securityContext.getAuthentication();
        System.out.println("authentication = " + authentication);
    }

}