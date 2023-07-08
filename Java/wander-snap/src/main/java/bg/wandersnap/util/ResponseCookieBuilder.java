package bg.wandersnap.util;

import jakarta.servlet.http.Cookie;

import static bg.wandersnap.common.Symbols.FORWARD_SLASH;

public class ResponseCookieBuilder {
    public static Cookie buildTokenCookie(final String token, final String cookieName, final int cookieExpTime) {
        final Cookie cookie = new Cookie(cookieName, token);
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
        cookie.setMaxAge(cookieExpTime);
        cookie.setPath(FORWARD_SLASH);

        return cookie;
    }
}