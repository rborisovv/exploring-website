package bg.wandersnap.resource;

import bg.wandersnap.domain.HttpGenericResponse;
import bg.wandersnap.dto.UserLoginDto;
import bg.wandersnap.exception.user.UserNotFoundException;
import bg.wandersnap.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthResource {
    private final AuthService authService;

    public AuthResource(final AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/csrf")
    public ResponseEntity<HttpGenericResponse> obtainCsrfToken() {
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping(value = "/login")
    public ResponseEntity<HttpGenericResponse> login(final @Valid @RequestBody UserLoginDto userCredentials,
                                                     final HttpServletResponse response) throws UserNotFoundException {

        final HttpGenericResponse httpGenericResponse = this.authService.loginUser(userCredentials, response);
        return new ResponseEntity<>(httpGenericResponse, HttpStatus.OK);
    }
}