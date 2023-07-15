package bg.wandersnap.service;

import bg.wandersnap.dao.RefreshTokenRepository;
import bg.wandersnap.dao.UserRepository;
import bg.wandersnap.domain.HttpGenericResponse;
import bg.wandersnap.dto.UserLoginDto;
import bg.wandersnap.enumeration.GdprConsentEnum;
import bg.wandersnap.exception.user.UserNotFoundException;
import bg.wandersnap.model.RefreshToken;
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
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static bg.wandersnap.common.JwtConstants.ACCESS_TOKEN_EXPIRATION_TIME_IN_S;
import static bg.wandersnap.common.JwtConstants.ACCESS_TOKEN_NAME;
import static bg.wandersnap.util.ResponseCookieBuilder.buildTokenCookie;

@Service
public class AuthService {
    private final UserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;
    private final TextEncryptor textEncryptor;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthService(final UserDetailsService userDetailsService, final AuthenticationManager authenticationManager, final UserRepository userRepository, final JwtProvider jwtProvider, final TextEncryptor textEncryptor, final RefreshTokenRepository refreshTokenRepository) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtProvider = jwtProvider;
        this.textEncryptor = textEncryptor;
        this.refreshTokenRepository = refreshTokenRepository;
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

        if (this.refreshTokenRepository.getRefreshTokenByUsername(username).isEmpty()) {
            this.addRefreshTokenToCurrentUser(user);
        }

        this.userRepository.save(user);

        final String accessToken = this.jwtProvider.generateAccessToken(userDetails);
        final Cookie accessTokenCookie = buildTokenCookie(accessToken, ACCESS_TOKEN_NAME, ACCESS_TOKEN_EXPIRATION_TIME_IN_S);

        response.addCookie(accessTokenCookie);

        return new HttpGenericResponse();
    }

    private void addRefreshTokenToCurrentUser(final User user) {
        final RefreshToken refreshToken = RefreshToken.builder()
                .token(this.textEncryptor.encrypt(UUID.randomUUID().toString()))
                .expirationTime(LocalDateTime.now().plusDays(30))
                .user(user)
                .build();

        this.refreshTokenRepository.save(refreshToken);
    }
}