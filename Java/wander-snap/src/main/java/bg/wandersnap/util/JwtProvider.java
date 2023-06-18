package bg.wandersnap.util;

import bg.wandersnap.dao.UserRepository;
import bg.wandersnap.exception.RsaKeyIntegrityViolationException;
import bg.wandersnap.exception.user.UserNotFoundException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static bg.wandersnap.common.ExceptionMessages.TOKEN_CANNOT_BE_VERIFIED;
import static java.util.Arrays.stream;

@Component
public class JwtProvider {
    private static final String TOKEN_ISSUER = "Wander-Snap";
    private static final String TOKEN_AUDIENCE = "Wander-Snap-audience";
    private static final String ROLES = "Roles";
    private static final String AUTHORITIES = "Authorities";

    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final RSAKeyProvider rsaKeyProvider;
    private final RsaKeyIntegrityVerifier rsaKeyIntegrityVerifier;

    public JwtProvider(final UserDetailsService userDetailsService, @Lazy final UserRepository userRepository,
                       final RSAKeyProvider rsaKeyProvider, final RsaKeyIntegrityVerifier rsaKeyIntegrityVerifier) {
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.rsaKeyProvider = rsaKeyProvider;
        this.rsaKeyIntegrityVerifier = rsaKeyIntegrityVerifier;
    }

    public String generateToken(@CurrentSecurityContext(expression = "authentication.name") final String username)
            throws IOException, NoSuchAlgorithmException, RsaKeyIntegrityViolationException {

        this.rsaKeyIntegrityVerifier.verifyRsaKeysIntegrity();
        final String[] claims = getClaimsFromUser(username);
        try {
            final long expireDurationInMs = 30 * 60 * 1000;

            final Algorithm algorithm = Algorithm.RSA256(this.rsaKeyProvider);
            return JWT.create()
                    .withIssuer(TOKEN_ISSUER)
                    .withAudience(TOKEN_AUDIENCE)
                    .withIssuedAt(new Date())
                    .withSubject(username)
                    .withArrayClaim(AUTHORITIES, claims)
                    .withClaim(ROLES, getRole(username))
                    .withExpiresAt(new Date(System.currentTimeMillis() + expireDurationInMs))
                    .sign(algorithm);
        } catch (final JWTCreationException exception) {
            throw new JWTCreationException(exception.getMessage(), exception.getCause());
        }
    }

    private List<String> getRole(final String username) {
        try {
            return this.userRepository.findByUsername(username).orElseThrow(UserNotFoundException::new)
                    .getRoles().stream().map(role -> role.getRole().name())
                    .collect(Collectors.toList());
        } catch (final UserNotFoundException ex) {
            throw new JWTCreationException(ex.getMessage(), ex);
        }
    }

    public String getSubject(final String token) {
        final JWTVerifier jwtVerifier = getJwtVerifier();
        return jwtVerifier.verify(token).getSubject();
    }

    public boolean isTokenValid(final String token) {
        final JWTVerifier jwtVerifier = getJwtVerifier();
        final String subject = getSubject(token);
        return StringUtils.isNotBlank(subject) && !isTokenExpired(jwtVerifier, token);
    }

    public Set<GrantedAuthority> getAuthorities(final String token) {
        final String username = this.getSubject(token);
        final String[] claims = getClaimsFromUser(username);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
    }

    private boolean isTokenExpired(final JWTVerifier jwtVerifier, final String token) {
        final Date expiration = jwtVerifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    private JWTVerifier getJwtVerifier() {
        try {
            final Algorithm algorithm = Algorithm.RSA256(this.rsaKeyProvider);
            return JWT.require(algorithm)
                    .withIssuer(TOKEN_ISSUER).build();
        } catch (final JWTVerificationException exception) {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
    }

    @SuppressWarnings("unused")
    private String[] getClaimsFromToken(final String token) {
        final JWTVerifier jwtVerifier = getJwtVerifier();
        return jwtVerifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }

    private String[] getClaimsFromUser(final String username) {
        final UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        return userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);
    }
}