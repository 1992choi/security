package io.security.springsecuritymaster.users.controller;

import io.security.springsecuritymaster.domain.dto.AccountDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping(value = "/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception, Model model) {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);

        return "login/login";
    }

    @GetMapping(value = "/signup")
    public String signup() {
        return "login/signup";
    }

    @GetMapping(value = "/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        if (authentication != null) {
            // 로그아웃 관련 핸들러는 많으나 세션을 무효화시키는 핸들러 선택
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }

    @GetMapping(value = "/denied")
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception,
                               @AuthenticationPrincipal AccountDto accountDto,
                               Model model) {
        // @AuthenticationPrincipal를 AccountDto로 받는 이유는 인증객체로 AccountDto를 사용했기 때문 (FormAuthenticationProvider.java의 authenticate() 메서드 참고)
        model.addAttribute("username", accountDto.getUsername());
        model.addAttribute("exception", exception);

        return "login/denied";
    }

}