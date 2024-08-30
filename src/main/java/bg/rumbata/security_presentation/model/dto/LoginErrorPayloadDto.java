package bg.rumbata.security_presentation.model.dto;

public record LoginErrorPayloadDto(

        String error,

        String message
) {
}