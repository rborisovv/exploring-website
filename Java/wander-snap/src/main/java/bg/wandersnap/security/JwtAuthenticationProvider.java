package bg.wandersnap.security;

import bg.wandersnap.exception.security.JwtTokenVerificationException;
import bg.wandersnap.exception.security.TokenExpiredException;
import bg.wandersnap.util.JwtProvider;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import static bg.wandersnap.common.ExceptionMessages.TOKEN_CANNOT_BE_VERIFIED;
import static bg.wandersnap.common.ExceptionMessages.TOKEN_EXPIRED;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtProvider jwtProvider;

    public JwtAuthenticationProvider(final @Lazy JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String jwtTokenCredentials = (String) authentication.getCredentials();
        final JWTVerifier jwtVerifier = this.jwtProvider.getAccessTokenVerifier();

        tokenPreAuthenticationChecks(jwtTokenCredentials);

        try {
            jwtVerifier.verify(jwtTokenCredentials);
        } catch (final JWTVerificationException ex) {
            throw new JwtTokenVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }

        return authentication;
    }

    private void tokenPreAuthenticationChecks(final String token) {
        if (this.jwtProvider.isExpiredToken(token)) {
            throw new TokenExpiredException(TOKEN_EXPIRED);
        }
    }

    @Override
    public boolean supports(final Class<?> authenticationType) {
        return JwtAuthenticationToken.class.isAssignableFrom(authenticationType);
    }
}