package bg.rumbata.security_presentation.service;

import bg.rumbata.security_presentation.model.MobileUser;
import bg.rumbata.security_presentation.model.MobileUserDetails;
import bg.rumbata.security_presentation.repository.MobileUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MobileUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final MobileUserRepository userRepository;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
        Optional<MobileUser> optionalMobileUser = userRepository.findByUsername(token.getName());
        if (optionalMobileUser.isEmpty()) {
            throw new UsernameNotFoundException(token.getName());
        }
        return new MobileUserDetails(optionalMobileUser.get());
    }
}
