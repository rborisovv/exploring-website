package bg.wandersnap.service;

import bg.wandersnap.common.ExceptionMessages;
import bg.wandersnap.dao.UserRepository;
import bg.wandersnap.model.Role;
import bg.wandersnap.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    public UserDetailsServiceImpl(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final User user = this.userRepository.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException(ExceptionMessages.USERNAME_NOT_FOUND_EXCEPTION));

        return this.userDetails(user);
    }

    private UserDetails userDetails(final User user) {
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(Arrays.toString(user.getRoles().toArray()))
                .authorities(this.mapAuthorities(user.getRoles()))
                .accountExpired(false)
                .accountLocked(false)
                .disabled(false)
                .credentialsExpired(false)
                .build();
    }

    private Set<GrantedAuthority> mapAuthorities(final Set<Role> roles) {
        return roles.stream()
                .flatMap(role -> role.getAuthorities().stream())
                .collect(Collectors.toSet());
    }
}
