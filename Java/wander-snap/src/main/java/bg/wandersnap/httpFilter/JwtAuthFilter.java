package bg.wandersnap.httpFilter;

import bg.wandersnap.exception.security.RsaKeyIntegrityViolationException;
import bg.wandersnap.util.JwtProvider;
import bg.wandersnap.util.RsaKeyIntegrityVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

import static bg.wandersnap.common.JwtConstants.JWT_COOKIE_NAME;
import static bg.wandersnap.common.JwtConstants.TOKEN_PREFIX;

@Component
public final class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtProvider jwtProvider;
    private final UserDetailsService userDetailsService;
    private final RsaKeyIntegrityVerifier rsaKeyIntegrityVerifier;

    public JwtAuthFilter(final JwtProvider jwtProvider, final UserDetailsService userDetailsService, final RsaKeyIntegrityVerifier rsaKeyIntegrityVerifier) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.rsaKeyIntegrityVerifier = rsaKeyIntegrityVerifier;
    }

    @Override
    @SuppressWarnings("nullness")
    protected void doFilterInternal(@NonNull final HttpServletRequest request, @NonNull final HttpServletResponse response, @NonNull final FilterChain filterChain) throws ServletException, IOException {
        try {
            this.rsaKeyIntegrityVerifier.verifyRsaKeysIntegrity();
        } catch (final NoSuchAlgorithmException | RsaKeyIntegrityViolationException e) {
            throw new ServletException(e);
        }

        final ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);

        if (requestWrapper.getMethod().equalsIgnoreCase(HttpMethod.OPTIONS.name())) {
            filterChain.doFilter(requestWrapper, response);
        }

        final String authorizationHeaders = requestWrapper.getHeader(JWT_COOKIE_NAME);

        if (authorizationHeaders == null || !authorizationHeaders.startsWith(TOKEN_PREFIX)) {
            filterChain.doFilter(requestWrapper, response);
            return;
        }

        final String token = authorizationHeaders.substring(TOKEN_PREFIX.length());
        final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

        if (jwtProvider.isTokenValid(token)) {
            final Set<GrantedAuthority> authorities = jwtProvider.getAuthorities(token);
            final String username = jwtProvider.getSubject(token);
            final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            final Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), authorities);
            securityContext.setAuthentication(authToken);
            SecurityContextHolder.setContext(securityContext);
        } else {
            SecurityContextHolder.clearContext();
        }
        filterChain.doFilter(requestWrapper, response);
    }
}