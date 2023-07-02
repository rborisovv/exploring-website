package bg.wandersnap.exception.security;

import org.springframework.security.core.AuthenticationException;

public class TokenExpiredException extends AuthenticationException {

    public TokenExpiredException(final String msg) {
        super(msg);
    }
}