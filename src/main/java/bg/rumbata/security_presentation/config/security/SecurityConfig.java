package bg.rumbata.security_presentation.config.security;

import bg.rumbata.security_presentation.config.security.formauth.FormLoginAuthProvider;
import bg.rumbata.security_presentation.config.security.headerauth.MobileHeaderFilter;
import bg.rumbata.security_presentation.config.security.headerauth.RequestHeaderAuthProvider;
import bg.rumbata.security_presentation.service.MobileFormUserDetailsService;
import bg.rumbata.security_presentation.service.MobileUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String REQUEST_HEADER_NAME = "X-Requested-H";
    private static final String REQUEST_HEADER_VALUE = "request-mobile";

    private final MobileUserDetailsService userDetailsService;
    private final MobileFormUserDetailsService mobileFormUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(security -> security
                        .requestMatchers("/cars/public").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(getMobileHeaderFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(getRequestHeaderFilter(), UsernamePasswordAuthenticationFilter.class)
                .httpBasic(withDefaults())
                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl("/cars/vip")
                        .failureForwardUrl("/login?error=true"))
                .authenticationManager(getAuthenticationManager())
                .build();
    }

    @Bean
    public AuthenticationManager getAuthenticationManager() {
        return new ProviderManager(Arrays.asList(new RequestHeaderAuthProvider(userDetailsService),
                new FormLoginAuthProvider(mobileFormUserDetailsService)));
    }

    private MobileHeaderFilter getMobileHeaderFilter() {
        return new MobileHeaderFilter();
    }

    private RequestHeaderAuthenticationFilter getRequestHeaderFilter() {
        RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter = new RequestHeaderAuthenticationFilter();
        requestHeaderAuthenticationFilter.setPrincipalRequestHeader(REQUEST_HEADER_NAME);
        requestHeaderAuthenticationFilter.setCredentialsRequestHeader(REQUEST_HEADER_VALUE);
        requestHeaderAuthenticationFilter.setExceptionIfHeaderMissing(false);
        requestHeaderAuthenticationFilter.setAuthenticationManager(getAuthenticationManager());
        return requestHeaderAuthenticationFilter;
    }
}
