package bg.wandersnap.httpFilter;

import bg.wandersnap.security.JwtAuthenticationToken;
import bg.wandersnap.util.JwtProvider;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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

import static bg.wandersnap.common.JwtConstants.*;

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

        final String accessToken = request.getHeader(ACCESS_TOKEN_HEADER_NAME);

        if (accessToken.isBlank() || !accessToken.startsWith(TOKEN_PREFIX)) {
            filterChain.doFilter(requestWrapper, response);
            return;
        }

        final String token = accessToken.substring(TOKEN_PREFIX.length());
        final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

        try {
            final Set<GrantedAuthority> authorities = this.jwtProvider.getAuthorities(token);
            final String username = this.jwtProvider.getSubject(token);
            final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            final Authentication authToken = new JwtAuthenticationToken(userDetails, token, authorities);
            final Authentication authentication = this.authenticationManager.authenticate(authToken);
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);
            filterChain.doFilter(request, response);
        } catch (final AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            throw new BadCredentialsException(ex.getMessage());
        } catch (final SignatureVerificationException ex) {
            response.sendError(HttpStatus.UNAUTHORIZED.value());
        }
    }
}