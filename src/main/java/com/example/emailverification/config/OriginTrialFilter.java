package com.example.emailverification.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Injects Origin-Trial HTTP response header when configured via environment variable
 */
@Component
public class OriginTrialFilter implements Filter {

    @Value("${email-verification.origin-trial-token:}")
    private String originTrialToken;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse httpResponse) {
            if (originTrialToken != null && !originTrialToken.isBlank()) {
                httpResponse.setHeader("Origin-Trial", originTrialToken.trim());
            }
        }
        chain.doFilter(request, response);
    }
}
