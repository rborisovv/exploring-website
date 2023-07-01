package bg.wandersnap.security;

import bg.wandersnap.annotation.VerifyRsaKeysIntegrity;
import bg.wandersnap.exception.security.JwtTokenVerificationException;
import bg.wandersnap.util.JwtProvider;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtProvider jwtProvider;

    public JwtAuthenticationProvider(final @Lazy JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    @VerifyRsaKeysIntegrity
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String jwtTokenCredentials = (String) authentication.getCredentials();
        final JWTVerifier jwtVerifier = this.jwtProvider.getJwtVerifier();

        try {
            jwtVerifier.verify(jwtTokenCredentials);
        } catch (final JWTVerificationException ex) {
            throw new JwtTokenVerificationException(ex.getMessage());
        }

        return authentication;
    }

    @Override
    public boolean supports(final Class<?> authenticationType) {
        return JwtAuthenticationToken.class.isAssignableFrom(authenticationType);
    }
}
