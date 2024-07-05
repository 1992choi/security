package io.security.springsecuritymaster;

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

}
