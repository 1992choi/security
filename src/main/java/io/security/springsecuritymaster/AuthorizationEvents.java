package io.security.springsecuritymaster;

import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationEvents {

    @EventListener
    public void onAuthorization(AuthorizationEvent event) {
        System.out.println("[AuthorizationEvent] event = " + event.getAuthentication().get().getAuthorities());
    }

    @EventListener
    public void onAuthorization(AuthorizationDeniedEvent failure) {
        System.out.println("[AuthorizationDeniedEvent] event = " + failure.getAuthentication().get().getAuthorities());
    }

    @EventListener
    public void onAuthorization(AuthorizationGrantedEvent success) {
        System.out.println("[AuthorizationGrantedEvent] event = " + success.getAuthentication().get().getAuthorities());
    }

}