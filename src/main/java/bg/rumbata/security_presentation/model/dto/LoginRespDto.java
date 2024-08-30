package bg.rumbata.security_presentation.model.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class LoginRespDto {

    private String username;

    private String token;

    private List<String> roles;

}
