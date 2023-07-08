package bg.wandersnap.common;

public record JwtConstants() {
    public static final String TOKEN_ISSUER = "Wander-Snap";
    public static final String TOKEN_AUDIENCE = "Wander-Snap Audience";
    public static final String AUTHORITIES = "Authorities";
    public static final String ROLES = "Roles";
    public static final long TOKEN_EXPIRATION_TIME_IN_S = 900;
    public static final int ACCESS_TOKEN_EXPIRATION_TIME_IN_S = 1_800;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String ACCESS_TOKEN_NAME = "access_token";
    public static final String ACCESS_TOKEN_HEADER_NAME = "Authorization";
}