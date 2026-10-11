package com.example.emailverification.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Serves index.html with server-side dynamic values (Origin Trial token & session nonce)
 */
@Controller
public class IndexController {

    @Value("${email-verification.origin-trial-token:}")
    private String originTrialToken;

    @Value("${email-verification.verifier.origin:http://localhost:8080}")
    private String verifierOrigin;

    private String htmlTemplate;

    private synchronized String getTemplate() throws IOException {
        if (htmlTemplate == null) {
            ClassPathResource resource = new ClassPathResource("static/index.html");
            htmlTemplate = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
        }
        return htmlTemplate;
    }

    @GetMapping(value = {"/", "/index.html"}, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> index(HttpSession session) throws IOException {
        String nonce = (String) session.getAttribute("EMAIL_VERIFICATION_NONCE");
        if (nonce == null) {
            nonce = UUID.randomUUID().toString();
            session.setAttribute("EMAIL_VERIFICATION_NONCE", nonce);
        }

        String html = getTemplate();

        // 1. Server-side Origin-Trial token injection
        String originTrialMetaTag = "";
        if (originTrialToken != null && !originTrialToken.isBlank()) {
            originTrialMetaTag = "<meta id=\"origin-trial-meta\" http-equiv=\"origin-trial\" content=\"" 
                    + originTrialToken.trim() + "\">";
        }
        html = html.replace("<!-- __ORIGIN_TRIAL_META__ -->", originTrialMetaTag);

        // 2. Server-side session nonce injection
        html = html.replace("__SESSION_NONCE__", nonce);

        HttpHeaders headers = new HttpHeaders();
        if (originTrialToken != null && !originTrialToken.isBlank()) {
            headers.set("Origin-Trial", originTrialToken.trim());
        }

        return ResponseEntity.ok()
                .headers(headers)
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }
}
