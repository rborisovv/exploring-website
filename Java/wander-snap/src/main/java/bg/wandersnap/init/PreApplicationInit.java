package bg.wandersnap.init;

import bg.wandersnap.dao.AuthorityRepository;
import bg.wandersnap.dao.RoleRepository;
import bg.wandersnap.dao.UserRepository;
import bg.wandersnap.enumeration.AuthorityEnum;
import bg.wandersnap.enumeration.RoleEnum;
import bg.wandersnap.model.Authority;
import bg.wandersnap.model.Role;
import bg.wandersnap.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.Set;

@Component
public class PreApplicationInit implements CommandLineRunner {
    private final RoleRepository roleRepository;
    private final AuthorityRepository authorityRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public PreApplicationInit(final RoleRepository roleRepository, final AuthorityRepository authorityRepository, final UserRepository userRepository, final PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.authorityRepository = authorityRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(final String... args) {
        if (roleRepository.count() > 0 || authorityRepository.count() > 0) {
            return;
        }

        final Set<Authority> userAuthorities = Set.of(
                new Authority(AuthorityEnum.READ_PRIVILEGE),
                new Authority(AuthorityEnum.WRITE_PRIVILEGE),
                new Authority(AuthorityEnum.UPDATE_PRIVILEGE),
                new Authority(AuthorityEnum.DELETE_PRIVILEGE)
        );


        final Set<Authority> adminAuthorities = Set.of(
                new Authority(AuthorityEnum.RESOURCE_MANAGEMENT_PRIVILEGE),
                new Authority(AuthorityEnum.ROLE_MANAGEMENT_PRIVILEGE),
                new Authority(AuthorityEnum.USER_MANAGEMENT_PRIVILEGE),
                new Authority(AuthorityEnum.SYSTEM_CONFIGURATION_PRIVILEGE)
        );

        this.authorityRepository.saveAll(userAuthorities);
        this.authorityRepository.saveAll(adminAuthorities);

        final Role userRole = new Role(RoleEnum.USER, userAuthorities);
        final Role adminRole = new Role(RoleEnum.ADMIN, adminAuthorities);
        final Set<Role> roles = Set.of(userRole, adminRole);

        this.roleRepository.save(userRole);
        this.roleRepository.save(adminRole);

        final User admin = User.builder().firstName("Radoslav").lastName("Borisov")
                .age(23).username("radi2000").password(this.passwordEncoder.encode("password"))
                .email("bradoslav00@gmail.com").birthDate(LocalDate.parse("2000-01-20"))
                .joinDate(LocalDate.now()).roles(roles).build();

        this.userRepository.save(admin);
    }
}