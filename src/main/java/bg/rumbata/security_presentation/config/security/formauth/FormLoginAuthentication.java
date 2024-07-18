package bg.rumbata.security_presentation.config.security.formauth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class FormLoginAuthentication implements Authentication {

    private final Object principal;

    private final Object credentials;

    private final Collection<? extends GrantedAuthority> authorities;

    private final boolean authenticated;

    private FormLoginAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = authorities;
        this.authenticated = credentials == null;
    }

    public static FormLoginAuthentication unauthenticated(Object principal, Object credentials) {
        return new FormLoginAuthentication(principal, credentials, Collections.emptyList());
    }

    public static FormLoginAuthentication authenticated(Object principal, Collection<? extends GrantedAuthority> authorities) {
        return new FormLoginAuthentication(principal, null, authorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.unmodifiableCollection(authorities);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        throw new UnsupportedOperationException("setAuthenticated() not supported");
    }

    @Override
    public String getName() {
        return principal.toString();
    }

    @Override
    public String toString() {
        return "%s [Principal=%s, Credentials=[PROTECTED], Authenticated=%b, Granted Authorities=%s"
                .formatted(getClass().getSimpleName(), principal, authenticated, authorities);
    }
}
