package bg.wandersnap.exception.security;

import org.springframework.security.core.AuthenticationException;


public class JwtTokenVerificationException extends AuthenticationException {
    public JwtTokenVerificationException(final String msg) {
        super(msg);
    }
}