package bg.wandersnap.model;

import bg.wandersnap.enumeration.AuthorityEnum;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "authorities")
public class Authority extends BaseEntity implements GrantedAuthority, Serializable {

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, unique = true)
    private AuthorityEnum authority;

    @Override
    public String getAuthority() {
        return authority.name();
    }
}