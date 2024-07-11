package io.security.springsecuritymaster;

import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AsyncService {

    @Async
    public void asyncMethod() {
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
        System.out.println("securityContext = " + securityContext);
        System.out.println("Child Thread: " + Thread.currentThread().getName());
        Authentication authentication = securityContext.getAuthentication();
        System.out.println("[Async] Authentication : " + authentication);
    }

}
