package bg.wandersnap.httpFilter;

import bg.wandersnap.security.JwtAuthenticationToken;
import bg.wandersnap.util.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
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
import java.util.Set;

import static bg.wandersnap.common.JwtConstants.JWT_COOKIE_NAME;
import static bg.wandersnap.common.JwtConstants.TOKEN_PREFIX;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtProvider jwtProvider;
    private final UserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;

    public JwtAuthFilter(final JwtProvider jwtProvider, final UserDetailsService userDetailsService, final AuthenticationManager authenticationManager) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
    }

    @Override
    @SuppressWarnings("nullness")
    protected void doFilterInternal(@NonNull final HttpServletRequest request, @NonNull final HttpServletResponse response, @NonNull final FilterChain filterChain) throws ServletException, IOException {
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
            final Authentication authToken = new JwtAuthenticationToken(userDetails, token, authorities);
            final Authentication authentication = this.authenticationManager.authenticate(authToken);
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);
        } else {
            SecurityContextHolder.clearContext();
        }
        filterChain.doFilter(requestWrapper, response);
    }
}