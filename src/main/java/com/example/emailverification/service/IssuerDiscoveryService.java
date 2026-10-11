package com.example.emailverification.service;

import com.example.emailverification.model.IssuerMetadata;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class IssuerDiscoveryService {
    private static final Logger log = LoggerFactory.getLogger(IssuerDiscoveryService.class);

    private final RestTemplate restTemplate;

    @Autowired(required = false)
    private MockIssuerService mockIssuerService;

    @org.springframework.beans.factory.annotation.Value("${email-verification.mock-issuer.enabled:true}")
    private boolean mockIssuerEnabled;

    @org.springframework.beans.factory.annotation.Value("${email-verification.mock-issuer.origin:http://localhost:8080}")
    private String mockIssuerOrigin;

    // Cache metadata and JWKS by issuer origin
    private final Map<String, IssuerMetadata> metadataCache = new ConcurrentHashMap<>();
    private final Map<String, JWKSet> jwksCache = new ConcurrentHashMap<>();

    public IssuerDiscoveryService() {
        this.restTemplate = new RestTemplate();
    }

    @Autowired(required = false)
    public IssuerDiscoveryService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate != null ? restTemplate : new RestTemplate();
    }

    /**
     * Discovers issuer configuration from `/.well-known/email-verification`
     */
    public IssuerMetadata discoverIssuer(String issuerOrigin) {
        if (issuerOrigin == null || issuerOrigin.isBlank()) {
            return null;
        }

        String normalizedOrigin = issuerOrigin.replaceAll("/+$", "");
        if (metadataCache.containsKey(normalizedOrigin)) {
            return metadataCache.get(normalizedOrigin);
        }

        // Check if matching internal mock issuer
        if (mockIssuerEnabled && mockIssuerService != null && isMockIssuerOrigin(normalizedOrigin)) {
            IssuerMetadata meta = mockIssuerService.getIssuerMetadata();
            metadataCache.put(normalizedOrigin, meta);
            return meta;
        }

        String wellKnownUrl = normalizedOrigin + "/.well-known/email-verification";
        log.info("Fetching issuer metadata from: {}", wellKnownUrl);

        try {
            ResponseEntity<IssuerMetadata> response = restTemplate.getForEntity(wellKnownUrl, IssuerMetadata.class);
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                IssuerMetadata meta = response.getBody();
                metadataCache.put(normalizedOrigin, meta);
                return meta;
            }
        } catch (Exception e) {
            log.error("Failed to fetch issuer metadata from {}: {}", wellKnownUrl, e.getMessage());
        }

        return null;
    }

    /**
     * Fetches the JWKSet from the issuer's jwks_uri
     */
    public JWKSet fetchJwks(String jwksUri) {
        if (jwksUri == null || jwksUri.isBlank()) {
            return null;
        }

        if (jwksCache.containsKey(jwksUri)) {
            return jwksCache.get(jwksUri);
        }

        // Check if matching internal mock issuer JWKS URI
        if (mockIssuerEnabled && mockIssuerService != null && isMockJwksUri(jwksUri)) {
            JWKSet jwkSet = mockIssuerService.getPublicJwks(true);
            jwksCache.put(jwksUri, jwkSet);
            return jwkSet;
        }

        log.info("Fetching JWKS from: {}", jwksUri);
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(jwksUri, String.class);
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                JWKSet jwkSet = JWKSet.parse(response.getBody());
                jwksCache.put(jwksUri, jwkSet);
                return jwkSet;
            }
        } catch (Exception e) {
            log.error("Failed to fetch or parse JWKS from {}: {}", jwksUri, e.getMessage());
        }

        return null;
    }

    private boolean isMockIssuerOrigin(String origin) {
        if (mockIssuerOrigin == null) return false;
        String mOrigin = mockIssuerOrigin.replaceAll("/+$", "");
        return origin.equalsIgnoreCase(mOrigin);
    }

    private boolean isMockJwksUri(String uri) {
        if (uri == null) return false;
        return uri.contains("/api/issuer/jwks");
    }

    public void clearCache() {
        metadataCache.clear();
        jwksCache.clear();
    }
}
