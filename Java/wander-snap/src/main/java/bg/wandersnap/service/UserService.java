package bg.wandersnap.service;

import bg.wandersnap.dao.UserRepository;
import bg.wandersnap.dto.UserProfileDto;
import bg.wandersnap.exception.user.UserNotFoundException;
import bg.wandersnap.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
        @Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    public UserProfileDto fetchProfileInformation(final UserDetails userDetails) throws UserNotFoundException {
        final String username = userDetails.getUsername();

        User user = this.userRepository.findByUsername(username).orElseThrow(UserNotFoundException::new);

        return null;
    }
}