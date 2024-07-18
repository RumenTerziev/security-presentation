package bg.rumbata.security_presentation.config.security.headerauth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class MobileHeaderFilter extends OncePerRequestFilter {

    private static final String MOBILE_HEADER_NAME = "X-Mobile";
    private static final String MOBILE_HEADER_VALUE = "mobile-le";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!request.getRequestURI().contains("/cars/vip/header")
            || SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        String headerValue = request.getHeader(MOBILE_HEADER_NAME);
        if (headerValue == null || !headerValue.equals(MOBILE_HEADER_VALUE)) {
            filterChain.doFilter(request, response);
            return;
        }

        SecurityContext newContext = SecurityContextHolder.createEmptyContext();
        newContext.setAuthentication(new UsernamePasswordAuthenticationToken(headerValue, null, Collections.emptyList()));
        SecurityContextHolder.setContext(newContext);
        filterChain.doFilter(request, response);
    }
}
