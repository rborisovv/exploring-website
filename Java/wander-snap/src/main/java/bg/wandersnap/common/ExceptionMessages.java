package bg.wandersnap.common;

public record ExceptionMessages() {
    public static final String USERNAME_NOT_FOUND_EXCEPTION = "A user with the provided username could not be found!";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "The provided token could not be verified!";
}