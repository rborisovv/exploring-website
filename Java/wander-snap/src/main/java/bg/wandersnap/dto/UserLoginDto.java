package bg.wandersnap.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
public class UserLoginDto {

    @NotBlank
    @Size(min = 5, max = 10)
    private String username;

    @NotBlank
    @Size(min = 6, max = 20)
    private String password;

    @NotNull
    private Map<String, Boolean> gdprConsent;
}