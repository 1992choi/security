package io.security.springsecuritymaster;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    private final SecurityContextService securityContextService;

    public IndexController(SecurityContextService securityContextService) {
        this.securityContextService = securityContextService;
    }

    @GetMapping("/")
    public String index() {
        securityContextService.securityContext();
        return "index";
    }

}
