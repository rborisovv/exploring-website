package bg.wandersnap.resource;

import bg.wandersnap.dto.UserProfileDto;
import bg.wandersnap.exception.user.UserNotFoundException;
import bg.wandersnap.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserResource {
    private final UserService userService;

    public UserResource(final UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/profile")
    @PreAuthorize("userDetails.accountNonExpired == false &&" +
            " userDetails.accountNonLocked == false &&" +
            " hasAnyRole('USER', 'ADMIN')")
    public UserProfileDto getUserProfile(
            @CurrentSecurityContext(expression = "authentication.principal")
            final UserDetails userDetails) throws UserNotFoundException {

        return this.userService.fetchProfileInformation(userDetails);
    }
}