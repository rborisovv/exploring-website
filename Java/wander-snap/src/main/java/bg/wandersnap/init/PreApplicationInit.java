package bg.wandersnap.init;

import bg.wandersnap.dao.AuthorityRepository;
import bg.wandersnap.dao.RoleRepository;
import bg.wandersnap.enumeration.AuthorityEnum;
import bg.wandersnap.model.Authority;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@Profile("Development")
public class PreApplicationInit implements CommandLineRunner {
    private final RoleRepository roleRepository;
    private final AuthorityRepository authorityRepository;

    public PreApplicationInit(final RoleRepository roleRepository, final AuthorityRepository authorityRepository) {
        this.roleRepository = roleRepository;
        this.authorityRepository = authorityRepository;
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
    }
}