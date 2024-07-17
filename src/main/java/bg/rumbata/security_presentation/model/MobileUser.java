package bg.rumbata.security_presentation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@Setter
@AllArgsConstructor
public class MobileUser {

    private String username;

    private String password;

    private String firstName;

    private String lastName;

    private Collection<? extends GrantedAuthority> authorities;
}
