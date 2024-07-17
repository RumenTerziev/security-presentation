package bg.rumbata.security_presentation.config;

import bg.rumbata.security_presentation.config.security.MobileHeaderFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(security -> security
                        .requestMatchers("/cars/public").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(getMobileHeaderFilter(), UsernamePasswordAuthenticationFilter.class)
                .httpBasic(withDefaults())
                .build();
    }

    private MobileHeaderFilter getMobileHeaderFilter() {
        return new MobileHeaderFilter();
    }
}
