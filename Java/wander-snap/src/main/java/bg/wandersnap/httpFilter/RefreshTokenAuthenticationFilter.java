package bg.wandersnap.httpFilter;

import bg.wandersnap.dao.RefreshTokenRepository;
import bg.wandersnap.exception.security.RefreshTokenExpiredException;
import bg.wandersnap.exception.security.RefreshTokenNotFoundException;
import bg.wandersnap.model.RefreshToken;
import bg.wandersnap.security.JwtAuthenticationToken;
import bg.wandersnap.util.JwtProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import static bg.wandersnap.common.JwtConstants.*;

@Order(1)
@Component
public class RefreshTokenAuthenticationFilter extends OncePerRequestFilter {
    private final JwtProvider jwtProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserDetailsService userDetailsService;
    private final TextEncryptor textEncryptor;
    private final AuthenticationManager authenticationManager;

    public RefreshTokenAuthenticationFilter(final JwtProvider jwtProvider,
                                            final RefreshTokenRepository refreshTokenRepository,
                                            final UserDetailsService userDetailsService,
                                            final TextEncryptor textEncryptor,
                                            final AuthenticationManager authenticationManager) {
        this.jwtProvider = jwtProvider;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userDetailsService = userDetailsService;
        this.textEncryptor = textEncryptor;
        this.authenticationManager = authenticationManager;
    }

    @Override
    @SuppressWarnings("nullness")
    protected void doFilterInternal(@NotNull final HttpServletRequest request,
                                    @NotNull final HttpServletResponse response,
                                    @NotNull final FilterChain filterChain) throws ServletException, IOException {

        String accessToken = request.getHeader(ACCESS_TOKEN_HEADER_NAME);

        if (accessToken == null || accessToken.substring(TOKEN_PREFIX.length() - 1).trim().isBlank() || !accessToken.startsWith(TOKEN_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        accessToken = accessToken.substring(TOKEN_PREFIX.length()).trim();

        try {
            this.jwtProvider.getAccessTokenVerifier().verify(accessToken);
        } catch (final JWTVerificationException ex) {
            final String subject = JWT.decode(accessToken).getSubject();

            final Optional<RefreshToken> optionalRefreshToken = this.refreshTokenRepository
                    .getRefreshTokenByUsername(subject);

            if (optionalRefreshToken.isEmpty()) {
                throw new RefreshTokenNotFoundException();
            }

            if (optionalRefreshToken.get().getExpirationTime().isBefore(LocalDateTime.now())) {
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                throw new RefreshTokenExpiredException();
            }

            final RefreshToken refreshToken = optionalRefreshToken.get();
            final UserDetails userDetails = this.userDetailsService.loadUserByUsername(subject);
            final String newAccessToken = this.jwtProvider.generateAccessToken(userDetails);

            refreshToken.setToken(this.textEncryptor.encrypt(UUID.randomUUID().toString()));
            refreshToken.setExpirationTime(LocalDateTime.now().plusDays(7));

            this.refreshTokenRepository.save(refreshToken);

            final var authenticationToken = new JwtAuthenticationToken(userDetails, newAccessToken, userDetails.getAuthorities());
            final Authentication authentication = this.authenticationManager.authenticate(authenticationToken);
            final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);

            updateAccessTokenForCurrentRequest(request, response, newAccessToken);
        } finally {
            filterChain.doFilter(request, response);
        }
    }

    private void updateAccessTokenForCurrentRequest(final HttpServletRequest request, final HttpServletResponse response,
                                                    final String newAccessToken) {
        Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(ACCESS_TOKEN_NAME))
                .findFirst()
                .ifPresent((cookie) -> {
                    cookie.setValue(newAccessToken);
                    cookie.setMaxAge(ACCESS_TOKEN_EXPIRATION_TIME_IN_S);

                    response.addCookie(cookie);
                });
    }
}