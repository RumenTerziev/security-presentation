package bg.rumbata.security_presentation.model.dto;

import java.util.List;

public record LoginRespDto(

        String username,

        String token,

        List<String> roles
) {
}
