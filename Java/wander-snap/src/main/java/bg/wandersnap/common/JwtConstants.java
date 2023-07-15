package bg.wandersnap.common;

public record JwtConstants() {
    public static final String TOKEN_ISSUER = "Wander-Snap";
    public static final String TOKEN_AUDIENCE = "Wander-Snap Audience";
    public static final String AUTHORITIES = "Authorities";
    public static final String ROLES = "Roles";
    public static final Integer ACCESS_TOKEN_EXPIRATION_TIME_IN_S = 2_629_743;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String ACCESS_TOKEN_NAME = "access_token";
    public static final String ACCESS_TOKEN_HEADER_NAME = "Authorization";
}