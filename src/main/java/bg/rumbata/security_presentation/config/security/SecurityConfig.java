package bg.rumbata.security_presentation.config.security;

import bg.rumbata.security_presentation.config.security.formauth.FormLoginAuthProvider;
import bg.rumbata.security_presentation.config.security.handler.LoginFailureHandler;
import bg.rumbata.security_presentation.config.security.handler.LoginSuccessHandler;
import bg.rumbata.security_presentation.config.security.headerauth.MobileHeaderFilter;
import bg.rumbata.security_presentation.config.security.headerauth.RequestHeaderAuthProvider;
import bg.rumbata.security_presentation.config.security.jwtauth.JwtAuthFilter;
import bg.rumbata.security_presentation.config.security.oauth.Oauth2Filter;
import bg.rumbata.security_presentation.service.JwtService;
import bg.rumbata.security_presentation.service.MobileFormUserDetailsService;
import bg.rumbata.security_presentation.service.MobileUserDetailsService;
import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String REQUEST_HEADER_NAME = "X-Requested-H";
    private static final String REQUEST_HEADER_VALUE = "request-mobile";

    private final MobileUserDetailsService userDetailsService;
    private final MobileFormUserDetailsService mobileFormUserDetailsService;
    private final JwtService jwtService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(security -> security
                        .requestMatchers("/cars/public").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(filterChainProxy(), AbstractPreAuthenticatedProcessingFilter.class)
                .httpBasic(withDefaults())
                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl("/cars/vip")
                        .failureForwardUrl("/login?error=true")
                        .successHandler(new LoginSuccessHandler(jwtService))
                        .failureHandler(new LoginFailureHandler()))
                .oauth2Login(oath -> oath
                        .failureUrl("/login?error=true")
                        .defaultSuccessUrl("/cars/vip"))
                .authenticationManager(getAuthenticationManager())
                .build();
    }

    @Bean
    public AuthenticationManager getAuthenticationManager() {
        return new ProviderManager(Arrays.asList(
                new RequestHeaderAuthProvider(userDetailsService),
                new FormLoginAuthProvider(mobileFormUserDetailsService),
                oidcAuthorizationCodeAuthenticationProvider(),
                oauth2AuthorizationCodeAuthenticationProvider()
        ));
    }

    @Bean
    public OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider() {
        return new OidcAuthorizationCodeAuthenticationProvider(oAuth2AccessTokenResponseClient(), oidcUserService());
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        return new OidcUserService();
    }

    @Bean
    public OAuth2AuthorizationCodeAuthenticationProvider oauth2AuthorizationCodeAuthenticationProvider() {
        return new OAuth2AuthorizationCodeAuthenticationProvider(oAuth2AccessTokenResponseClient());
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oAuth2AccessTokenResponseClient() {
        return new DefaultAuthorizationCodeTokenResponseClient();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        return new DefaultOAuth2UserService();
    }

    private FilterChainProxy filterChainProxy() {
        return new FilterChainProxy(Arrays.asList(
                mobileHeaderChain(),
                requestHeaderChain(),
                jwtChain(),
                oathChain()
        ));
    }

    private DefaultSecurityFilterChain mobileHeaderChain() {
        AntPathRequestMatcher mobileHeaderMatcher = new AntPathRequestMatcher("/cars/vip/header");
        List<Filter> mobileHeaderList = List.of(getMobileHeaderFilter());
        return new DefaultSecurityFilterChain(mobileHeaderMatcher, mobileHeaderList);
    }

    private DefaultSecurityFilterChain requestHeaderChain() {
        AntPathRequestMatcher requestMatcher = new AntPathRequestMatcher("/cars/vip/req-header");
        List<Filter> requestHeaderList = List.of(getRequestHeaderFilter());
        return new DefaultSecurityFilterChain(requestMatcher, requestHeaderList);
    }

    private DefaultSecurityFilterChain jwtChain() {
        AntPathRequestMatcher jwtMatcher = new AntPathRequestMatcher("/cars/vip/jwt");
        List<Filter> jwtList = List.of(new JwtAuthFilter(jwtService, mobileFormUserDetailsService));
        return new DefaultSecurityFilterChain(jwtMatcher, jwtList);
    }

    private DefaultSecurityFilterChain oathChain() {
        AntPathRequestMatcher oathMatcher = new AntPathRequestMatcher("/cars/vip/oath");
        List<Filter> oathList = List.of(new Oauth2Filter());
        return new DefaultSecurityFilterChain(oathMatcher, oathList);
    }

    private MobileHeaderFilter getMobileHeaderFilter() {
        return new MobileHeaderFilter();
    }

    private RequestHeaderAuthenticationFilter getRequestHeaderFilter() {
        RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter = new RequestHeaderAuthenticationFilter();
        requestHeaderAuthenticationFilter.setPrincipalRequestHeader(REQUEST_HEADER_NAME);
        requestHeaderAuthenticationFilter.setCredentialsRequestHeader(REQUEST_HEADER_VALUE);
        requestHeaderAuthenticationFilter.setExceptionIfHeaderMissing(false);
        return requestHeaderAuthenticationFilter;
    }
}
