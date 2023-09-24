package bg.wandersnap.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

@AllArgsConstructor
@Getter
@Setter
@ToString
public class UserProfileDto implements Serializable {
    private String username;

    private String firstName;

    private String lastName;

    private String phone;

    private String email;
}