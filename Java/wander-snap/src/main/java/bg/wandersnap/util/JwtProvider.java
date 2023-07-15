package bg.wandersnap.util;

import bg.wandersnap.dao.UserRepository;
import bg.wandersnap.exception.user.UserNotFoundException;
import bg.wandersnap.security.RsaInMemoryKeyProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static bg.wandersnap.common.JwtConstants.*;
import static java.util.Arrays.stream;

@Component
public class JwtProvider {
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final RsaInMemoryKeyProvider rsaInMemoryKeyProvider;
    @Qualifier("classPathRsaKeyProvider")
    private final RSAKeyProvider rsaKeyProvider;

    public JwtProvider(final UserDetailsService userDetailsService, final UserRepository userRepository,
                       final RsaInMemoryKeyProvider rsaInMemoryKeyProvider, final RSAKeyProvider rsaKeyProvider) {
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.rsaInMemoryKeyProvider = rsaInMemoryKeyProvider;
        this.rsaKeyProvider = rsaKeyProvider;
    }

    public String generateAccessToken(@CurrentSecurityContext(expression = "authentication.principal") final UserDetails userDetails) {

        final String[] claims = getClaimsFromUser(userDetails);
        try {
            final Algorithm algorithm = Algorithm.RSA256(this.rsaInMemoryKeyProvider.getRsaPublicKey(),
                    this.rsaInMemoryKeyProvider.getRsaPrivateKey());

            return JWT.create()
                    .withIssuer(TOKEN_ISSUER)
                    .withAudience(TOKEN_AUDIENCE)
                    .withIssuedAt(Instant.now())
                    .withSubject(userDetails.getUsername())
                    .withArrayClaim(AUTHORITIES, claims)
                    .withClaim(ROLES, getRole(userDetails.getUsername()))
                    .withNotBefore(Instant.now().minus(30, ChronoUnit.MINUTES))
                    .withExpiresAt(Instant.now().plus(30, ChronoUnit.MINUTES))
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
        final JWTVerifier jwtVerifier = getAccessTokenVerifier();
        return jwtVerifier.verify(token).getSubject();
    }

    public boolean isExpiredToken(final String token) {
        final JWTVerifier jwtVerifier = getAccessTokenVerifier();
        final String subject = getSubject(token);
        return StringUtils.isNotBlank(subject) && isTokenExpired(jwtVerifier, token);
    }

    public Set<GrantedAuthority> getAuthorities(final String token) {
        final String username = this.getSubject(token);
        final String[] claims = getClaimsFromUser(username);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toUnmodifiableSet());
    }

    private boolean isTokenExpired(final JWTVerifier jwtVerifier, final String token) {
        final Date expiration = jwtVerifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    public JWTVerifier getAccessTokenVerifier() {
        final Algorithm algorithm = Algorithm.RSA256(this.rsaInMemoryKeyProvider.getRsaPublicKey(),
                this.rsaInMemoryKeyProvider.getRsaPrivateKey());

        return JWT.require(algorithm)
                .withIssuer(TOKEN_ISSUER)
                .withAudience(TOKEN_AUDIENCE)
                .acceptNotBefore((System.currentTimeMillis() / 1000) - ACCESS_TOKEN_EXPIRATION_TIME_IN_S)
                .acceptExpiresAt((System.currentTimeMillis() / 1000) + ACCESS_TOKEN_EXPIRATION_TIME_IN_S)
                .build();
    }

    @SuppressWarnings("unused")
    private String[] getClaimsFromToken(final String token) {
        final JWTVerifier jwtVerifier = getAccessTokenVerifier();
        return jwtVerifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }

    private String[] getClaimsFromUser(@CurrentSecurityContext(expression = "authentication.principal") final UserDetails userDetails) {

        return userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);
    }

    private String[] getClaimsFromUser(final String username) {
        final UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

        return userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);
    }
}