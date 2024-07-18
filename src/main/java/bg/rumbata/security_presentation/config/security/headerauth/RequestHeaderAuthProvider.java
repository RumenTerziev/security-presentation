package bg.rumbata.security_presentation.config.security.headerauth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@RequiredArgsConstructor
public class RequestHeaderAuthProvider extends PreAuthenticatedAuthenticationProvider {

    private final AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> mobileUserDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof PreAuthenticatedAuthenticationToken token)) {
            return null;
        }
        Object principal = token.getPrincipal();
        Object credentials = token.getCredentials();
        UserDetails userDetails = mobileUserDetailsService.loadUserDetails(token);
        return new PreAuthenticatedAuthenticationToken(principal, credentials, userDetails.getAuthorities());
    }
}
