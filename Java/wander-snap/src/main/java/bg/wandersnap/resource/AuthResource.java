package bg.wandersnap.resource;

import bg.wandersnap.dto.UserLoginDto;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthResource {

    @GetMapping("/csrf")
    public void obtainCsrfToken() {

    }

    @PostMapping("/login")
    public void login(final @Valid @RequestBody UserLoginDto userLoginDto) {
        System.out.println(userLoginDto);
    }
}