package bg.wandersnap.aspect;

import bg.wandersnap.exception.security.JwtTokenVerificationException;
import bg.wandersnap.exception.security.RsaKeyIntegrityViolationException;
import bg.wandersnap.security.RsaKeyIntegrityVerifier;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@Aspect
@Component
public class RsaRefreshKeyIntegrityVerifierAspect {
    private final RsaKeyIntegrityVerifier rsaKeyIntegrityVerifier;

    public RsaRefreshKeyIntegrityVerifierAspect(final RsaKeyIntegrityVerifier rsaKeyIntegrityVerifier) {
        this.rsaKeyIntegrityVerifier = rsaKeyIntegrityVerifier;
    }

    @Before("@annotation(bg.wandersnap.annotation.VerifyRsaKeysIntegrity)")
    public void beforeTokenInvocation() {
        try {
            this.rsaKeyIntegrityVerifier.verifyRsaKeysIntegrity();
        } catch (final NoSuchAlgorithmException | RsaKeyIntegrityViolationException | IOException ex) {
            throw new JwtTokenVerificationException(ex.getMessage());
        }
    }
}