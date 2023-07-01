package bg.wandersnap.service;

import bg.wandersnap.dao.UserRepository;
import bg.wandersnap.domain.HttpGenericResponse;
import bg.wandersnap.dto.UserLoginDto;
import bg.wandersnap.enumeration.GdprConsentEnum;
import bg.wandersnap.exception.user.UserNotFoundException;
import bg.wandersnap.model.User;
import bg.wandersnap.util.JwtProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static bg.wandersnap.common.JwtConstants.JWT_COOKIE_NAME;
import static bg.wandersnap.common.JwtConstants.TOKEN_EXPIRATION_TIME_IN_S;
import static bg.wandersnap.common.Symbols.FORWARD_SLASH;

@Service
public class AuthService {
    private final UserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;

    public AuthService(final UserDetailsService userDetailsService, final AuthenticationManager authenticationManager, final UserRepository userRepository, final JwtProvider jwtProvider) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtProvider = jwtProvider;
    }


    public HttpGenericResponse loginUser(final UserLoginDto userCredentials, final HttpServletResponse response) throws UserNotFoundException {
        final String username = userCredentials.getUsername();
        final String password = userCredentials.getPassword();

        final UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

        final var usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, password,
                userDetails.getAuthorities());

        final Authentication authentication = this.authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);

        final Set<GdprConsentEnum> gdprConsent = userCredentials
                .getGdprConsent()
                .keySet()
                .stream()
                .map(String::toUpperCase)
                .map(GdprConsentEnum::valueOf)
                .collect(Collectors.toSet());

        final User user = this.userRepository.findByUsername(username).orElseThrow(UserNotFoundException::new);
        Set<GdprConsentEnum> userGdprConsentCollection = user.getGdprConsent();
        if (userGdprConsentCollection == null) {
            userGdprConsentCollection = new HashSet<>();
        }
        userGdprConsentCollection.addAll(gdprConsent);
        this.userRepository.save(user);

        final String jwtToken = this.jwtProvider.generateToken(userDetails);
        final Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, jwtToken);

        jwtCookie.setHttpOnly(false);
        jwtCookie.setSecure(false);
        jwtCookie.setMaxAge(TOKEN_EXPIRATION_TIME_IN_S);
        jwtCookie.setPath(FORWARD_SLASH);

        response.addCookie(jwtCookie);

        return new HttpGenericResponse();
    }
}