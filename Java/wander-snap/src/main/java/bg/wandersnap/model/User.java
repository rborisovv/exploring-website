package bg.wandersnap.model;

import bg.wandersnap.enumeration.GdprConsentEnum;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "users")
public class User extends BaseEntity implements Serializable {
    @Column(nullable = false, length = 40)
    private String firstName;

    @Column(nullable = false, length = 40)
    private String lastName;

    @Column(nullable = false)
    private LocalDate birthDate;

    @Column
    private Integer age;

    @Column(nullable = false, unique = true, length = 10)
    private String username;

    @Column(nullable = false, length = 120)
    private String password;

    @Column(unique = true, length = 25)
    private String email;

    @ManyToMany
    private Set<Role> roles;

    @Enumerated(EnumType.STRING)
    private Set<GdprConsentEnum> gdprConsent;

    @Column(nullable = false)
    private LocalDate joinDate;
}