package bg.wandersnap.config;

import bg.wandersnap.dao.UserRepository;
import bg.wandersnap.httpFilter.AccessTokenAuthenticationFilter;
import bg.wandersnap.httpFilter.RefreshTokenAuthenticationFilter;
import bg.wandersnap.security.JwtAuthenticationProvider;
import bg.wandersnap.security.RsaKeyProviderFactory;
import bg.wandersnap.service.UserDetailsServiceImpl;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true)
public class SecurityConfiguration {
    private static final String[] PUBLIC_URLS = {
            "/auth/csrf",
            "/auth/login"
    };

    private final UserRepository userRepository;
    private final ResourceLoader resourceLoader;
    private final AccessTokenAuthenticationFilter accessTokenAuthenticationFilter;
    private final RefreshTokenAuthenticationFilter refreshTokenAuthenticationFilter;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public SecurityConfiguration(final UserRepository userRepository,
                                 final ResourceLoader resourceLoader,
                                 final @Lazy AccessTokenAuthenticationFilter accessTokenAuthenticationFilter,
                                 final @Lazy RefreshTokenAuthenticationFilter refreshTokenAuthenticationFilter,
                                 final JwtAuthenticationProvider jwtAuthenticationProvider
    ) {

        this.userRepository = userRepository;
        this.resourceLoader = resourceLoader;
        this.accessTokenAuthenticationFilter = accessTokenAuthenticationFilter;
        this.refreshTokenAuthenticationFilter = refreshTokenAuthenticationFilter;
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity httpSecurity) throws Exception {
        final CookieCsrfTokenRepository tokenRepository = new CookieCsrfTokenRepository();
        tokenRepository.setCookieCustomizer(responseCookieBuilder -> responseCookieBuilder.httpOnly(false).build());

        final XorCsrfTokenRequestAttributeHandler delegate = new XorCsrfTokenRequestAttributeHandler();

        delegate.setCsrfRequestAttributeName(null);
        final CsrfTokenRequestHandler requestHandler = delegate::handle;

        return httpSecurity
                .cors(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf((csrf) -> csrf
                        .csrfTokenRepository(tokenRepository)
                        .csrfTokenRequestHandler(requestHandler))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_URLS)
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .addFilterBefore(refreshTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(accessTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin((form) -> form
                        .successHandler((req, res, auth) -> res.setStatus(HttpStatus.OK.value()))
                        .failureHandler((req, res, auth) -> res.setStatus(HttpStatus.UNAUTHORIZED.value()))
                )
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Bean
    public AuthenticationManager authManager(final HttpSecurity http) throws Exception {
        final AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(jwtAuthenticationProvider);

        final DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(this.userDetailsService());
        daoAuthenticationProvider.setPasswordEncoder(this.passwordEncoder());
        authenticationManagerBuilder.authenticationProvider(daoAuthenticationProvider);

        return authenticationManagerBuilder.build();
    }

    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        corsConfiguration.setAllowedHeaders(Arrays.asList("Origin", "Access-Control-Allow-Origin", "Content-Type",
                "Accept", "Access-Token", "Authorization", "X-Request-With", "Access-Control-Request-Method",
                "Access-Control-Request-Headers", "XSRF-TOKEN", "X-XSRF-TOKEN"));
        corsConfiguration.setExposedHeaders(Arrays.asList("Origin", "Content-Type", "Accept",
                "Authorization", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "XSRF-TOKEN", "X-XSRF-TOKEN"));
        corsConfiguration.setAllowedMethods(Arrays.asList(
                HttpMethod.GET.name(), HttpMethod.POST.name(),
                HttpMethod.PUT.name(), HttpMethod.PATCH.name(),
                HttpMethod.DELETE.name(), HttpMethod.OPTIONS.name()
        ));
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
        return new CorsFilter(urlBasedCorsConfigurationSource);
    }

    @Bean
    public static RoleHierarchy roleHierarchy() {
        final var hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("""
                ROLE_ADMIN > ROLE_USER
                """);

        return hierarchy;
    }

    @Bean
    public static MethodSecurityExpressionHandler methodSecurityExpressionHandler(final RoleHierarchy roleHierarchy) {
        final DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy);
        return expressionHandler;
    }

    @Bean
    @Profile("Production")
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl(this.userRepository);
    }

    @Bean("classPathRsaKeyProvider")
    public RSAKeyProvider rsaKeyProvider() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        final Resource privateKeyPath = resourceLoader.getResource("classpath:keys/private_key.pem");
        final Resource publicKeyPath = resourceLoader.getResource("classpath:keys/public_key.pem");
        final byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyPath.getURI()));
        final byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyPath.getURI()));

        final byte[] decodedPrivateKey = decodeRsaKeyContent(privateKeyBytes);
        final byte[] decodedPublicKey = decodeRsaKeyContent(publicKeyBytes);
        final PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
        final X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(decodedPublicKey);

        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateSpec);
        final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicSpec);
        return new RsaKeyProviderFactory(privateKey, publicKey);
    }

    private byte[] decodeRsaKeyContent(final byte[] rsaKeyBytes) {
        final String rsaKeyContent = new String(rsaKeyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", StringUtils.EMPTY)
                .replace("-----BEGIN PUBLIC KEY-----", StringUtils.EMPTY)
                .replace("-----END PRIVATE KEY-----", StringUtils.EMPTY)
                .replace("-----END PUBLIC KEY-----", StringUtils.EMPTY)
                .replaceAll("\\s+", StringUtils.EMPTY);

        return Base64.getDecoder().decode(rsaKeyContent);
    }
}