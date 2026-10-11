package com.example.emailverification.controller;

import com.example.emailverification.model.IssuerMetadata;
import com.example.emailverification.service.MockIssuerService;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class MockIssuerController {

    private final MockIssuerService mockIssuerService;

    public MockIssuerController(MockIssuerService mockIssuerService) {
        this.mockIssuerService = mockIssuerService;
    }

    /**
     * Chrome / Verifier discovery metadata endpoint:
     * GET /.well-known/email-verification
     */
    @GetMapping(value = "/.well-known/email-verification", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IssuerMetadata> getWellKnownMetadata() {
        return ResponseEntity.ok(mockIssuerService.getIssuerMetadata());
    }

    /**
     * Public JWKS endpoint:
     * GET /api/issuer/jwks
     */
    @GetMapping(value = "/api/issuer/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getPublicJwks(
            @RequestParam(name = "includeKid", defaultValue = "true") boolean includeKid) {
        JWKSet jwkSet = mockIssuerService.getPublicJwks(includeKid);
        return ResponseEntity.ok(jwkSet.toString());
    }

    /**
     * Test endpoint: generate a real RFC 9901 SD-JWT+KB sample token
     */
    @PostMapping(value = "/api/issuer/generate-sample-token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> generateSampleToken(
            @RequestBody Map<String, Object> req) {
        try {
            String email = (String) req.getOrDefault("email", "demo@example.com");
            String nonce = (String) req.get("nonce");
            String aud = (String) req.get("aud");
            boolean includeKid = Boolean.parseBoolean(String.valueOf(req.getOrDefault("includeKid", "true")));

            String token = mockIssuerService.generateSampleToken(email, nonce, aud, includeKid);

            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "email", email,
                    "nonce", nonce != null ? nonce : "",
                    "includeKid", includeKid,
                    "length", token.length()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
