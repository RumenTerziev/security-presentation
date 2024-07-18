package bg.rumbata.security_presentation.service;

import bg.rumbata.security_presentation.model.MobileUser;
import bg.rumbata.security_presentation.model.MobileUserDetails;
import bg.rumbata.security_presentation.repository.MobileUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MobileFormUserDetailsService implements UserDetailsService {

    private final MobileUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<MobileUser> optionalMobileUser = userRepository.findByUsername(username);
        if (optionalMobileUser.isEmpty()) {
            throw new UsernameNotFoundException(username);
        }
        return new MobileUserDetails(optionalMobileUser.get());
    }
}
