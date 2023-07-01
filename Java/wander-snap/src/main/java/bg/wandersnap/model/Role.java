package bg.wandersnap.model;

import bg.wandersnap.enumeration.RoleEnum;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.Objects;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "roles")
public class Role extends BaseEntity implements Serializable {

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private RoleEnum role;

    @ManyToMany
    private Set<Authority> authorities;

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final Role role1 = (Role) o;
        return role == role1.role;
    }

    @Override
    public int hashCode() {
        return Objects.hash(role);
    }

    @Override
    public String toString() {
        return role.name();
    }
}