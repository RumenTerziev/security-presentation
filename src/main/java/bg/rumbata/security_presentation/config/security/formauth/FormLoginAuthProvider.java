package bg.rumbata.security_presentation.config.security.formauth;


import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

@RequiredArgsConstructor
public class FormLoginAuthProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        FormLoginAuthentication authRequest = FormLoginAuthentication
                .unauthenticated(authentication.getPrincipal(), authentication.getCredentials());

        UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getName());

        if (!authRequest.getCredentials().toString().equals(userDetails.getPassword())) {
            throw new BadCredentialsException("Incorrect username or password!");
        }
        return FormLoginAuthentication.authenticated(userDetails.getUsername(), userDetails, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
