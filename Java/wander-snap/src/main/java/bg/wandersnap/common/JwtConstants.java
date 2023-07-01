package bg.wandersnap.common;

public record JwtConstants() {
    public static final String TOKEN_ISSUER = "Wander-Snap";
    public static final String TOKEN_AUDIENCE = "Wander-Snap Audience";
    public static final String AUTHORITIES = "Authorities";
    public static final String ROLES = "Roles";
    public static final long TOKEN_EXPIRATION_TIME_IN_MS = 30 * 60 * 1000;
    public static final int TOKEN_EXPIRATION_TIME_IN_S = 1_800;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_COOKIE_NAME = "JWT-TOKEN";
}