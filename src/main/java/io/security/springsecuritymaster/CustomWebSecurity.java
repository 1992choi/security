package io.security.springsecuritymaster;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component("customWebSecurity")
public class CustomWebSecurity {

    public boolean check(Authentication authentication, HttpServletRequest request) {
        // 권한 체크 로직을 구현하면 된다.
        return authentication.isAuthenticated();
    }

}