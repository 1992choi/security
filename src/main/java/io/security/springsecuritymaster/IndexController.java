package io.security.springsecuritymaster;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping("/csrf")
    public String csrf(){
        return "csrf 적용";
    }

    @GetMapping("/csrfToken")
    public String csrfToken(HttpServletRequest request) {
        CsrfToken csrfToken1 = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        CsrfToken csrfToken2 = (CsrfToken) request.getAttribute("_csrf");

        System.out.println("csrfToken1: " + csrfToken1);
        System.out.println("csrfToken2: " + csrfToken2);

        String token = csrfToken1.getToken();
        return token;
    }

}
