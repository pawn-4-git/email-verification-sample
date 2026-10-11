package com.example.emailverification.service;

import com.example.emailverification.model.IssuerMetadata;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

@Service
public class MockIssuerService {
    private static final Logger log = LoggerFactory.getLogger(MockIssuerService.class);

    @Value("${email-verification.mock-issuer.origin:http://localhost:8080}")
    private String issuerOrigin;

    private OctetKeyPair issuerKeyPair;
    private static final String DEFAULT_KID = "mock-issuer-key-2026";

    @PostConstruct
    public synchronized void init() {
        if (issuerKeyPair != null) {
            return;
        }
        try {
            // Generate Ed25519 key pair for mock issuer
            issuerKeyPair = new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyID(DEFAULT_KID)
                    .generate();
            log.info("Initialized Mock Issuer with Ed25519 key ID: {}", DEFAULT_KID);
        } catch (Exception e) {
            log.error("Failed to generate mock issuer key pair: {}", e.getMessage(), e);
        }
    }

    /**
     * Return /.well-known/email-verification metadata
     */
    public IssuerMetadata getIssuerMetadata() {
        String base = issuerOrigin.replaceAll("/+$", "");
        return new IssuerMetadata(
                base + "/api/issuer/issue",
                base + "/api/issuer/jwks",
                List.of("EdDSA", "ES256")
        );
    }

    /**
     * Return public JWKS
     */
    public JWKSet getPublicJwks(boolean includeKidInJwks) {
        if (issuerKeyPair == null) return new JWKSet();
        OctetKeyPair pub = issuerKeyPair.toPublicJWK();
        if (!includeKidInJwks) {
            // Strip kid to test candidate key iteration matching!
            pub = new OctetKeyPair.Builder(pub.getCurve(), pub.getX())
                    .algorithm(JWSAlgorithm.EdDSA)
                    .build();
        }
        return new JWKSet(pub);
    }

    /**
     * Helper to simulate a browser generating a valid RFC 9901 SD-JWT+KB token.
     * Can omit kid to simulate Gmail / Chrome October 2026 update behavior.
     */
    public String generateSampleToken(String email, String nonce, String aud, boolean includeKid) throws Exception {
        if (issuerKeyPair == null) {
            init();
        }

        Instant now = Instant.now();
        Instant exp = now.plusSeconds(300); // 5 minutes validity

        // 1. Generate browser ephemeral key pair (Ed25519)
        OctetKeyPair browserEphemeralKeyPair = new OctetKeyPairGenerator(Curve.Ed25519)
                .generate();
        Map<String, Object> browserPublicJwkMap = browserEphemeralKeyPair.toPublicJWK().toJSONObject();

        // 2. Build EVT payload
        Map<String, Object> cnf = Map.of("jwk", browserPublicJwkMap);

        JWTClaimsSet.Builder evtClaimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuerOrigin.replaceAll("/+$", ""))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp))
                .claim("email", email)
                .claim("email_verified", true)
                .claim("cnf", cnf);

        JWTClaimsSet evtClaims = evtClaimsBuilder.build();

        // 3. Build EVT Header (optionally including or omitting kid)
        JWSHeader.Builder evtHeaderBuilder = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new com.nimbusds.jose.JOSEObjectType("evt+jwt"));
        if (includeKid) {
            evtHeaderBuilder.keyID(issuerKeyPair.getKeyID());
        }
        JWSHeader evtHeader = evtHeaderBuilder.build();

        // 4. Sign EVT with Issuer Private Key
        SignedJWT evtSignedJwt = new SignedJWT(evtHeader, evtClaims);
        evtSignedJwt.sign(new Ed25519Signer(issuerKeyPair));
        String evtCompact = evtSignedJwt.serialize();

        // 5. Compute SHA-256 sd_hash for Key Binding JWT
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest((evtCompact + "~").getBytes(StandardCharsets.US_ASCII));
        String sdHash = Base64URL.encode(hash).toString();

        // 6. Build KB-JWT payload
        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience(aud != null ? aud : issuerOrigin)
                .issueTime(Date.from(now))
                .claim("nonce", nonce != null ? nonce : UUID.randomUUID().toString())
                .claim("sd_hash", sdHash)
                .build();

        // 7. Sign KB-JWT with Browser Ephemeral Private Key
        JWSHeader kbHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new com.nimbusds.jose.JOSEObjectType("kb+jwt"))
                .build();
        SignedJWT kbSignedJwt = new SignedJWT(kbHeader, kbClaims);
        kbSignedJwt.sign(new Ed25519Signer(browserEphemeralKeyPair));
        String kbCompact = kbSignedJwt.serialize();

        // 8. Combine into RFC 9901 SD-JWT format: <EVT>~<KB-JWT>
        return evtCompact + "~" + kbCompact;
    }
}
