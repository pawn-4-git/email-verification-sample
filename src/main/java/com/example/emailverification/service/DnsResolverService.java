package com.example.emailverification.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.net.URI;
import java.util.*;

@Service
public class DnsResolverService {
    private static final Logger log = LoggerFactory.getLogger(DnsResolverService.class);

    @Value("${email-verification.mock-issuer.enabled:true}")
    private boolean mockIssuerEnabled;

    @Value("${email-verification.mock-issuer.origin:http://localhost:8080}")
    private String mockIssuerOrigin;

    @Value("${email-verification.mock-issuer.supported-domains:example.com,provider.example,localhost,test.local}")
    private List<String> mockSupportedDomains;

    /**
     * Resolves the DNS TXT record for `_email-verification.<emailDomain>`
     * to verify the issuer authority delegation.
     * Expected format: "iss=<issuer-domain>"
     *
     * @param emailDomain the domain of the email address (e.g., "gmail.com")
     * @return the issuer host or null if not found
     */
    public String resolveIssuerDomain(String emailDomain) {
        if (emailDomain == null || emailDomain.isBlank()) {
            return null;
        }

        String normalizedDomain = emailDomain.trim().toLowerCase();

        // 1. Check local / mock test domains for seamless development and testing
        if (mockIssuerEnabled && isMockDomain(normalizedDomain)) {
            try {
                URI uri = URI.create(mockIssuerOrigin);
                String host = uri.getHost();
                if (uri.getPort() != -1 && uri.getPort() != 80 && uri.getPort() != 443) {
                    host = host + ":" + uri.getPort();
                }
                log.info("Using mock DNS delegation for {}: iss={}", normalizedDomain, host);
                return host;
            } catch (Exception e) {
                log.warn("Failed to parse mock issuer origin: {}", mockIssuerOrigin);
            }
        }

        // 2. Perform real DNS TXT record query: _email-verification.<domain>
        String queryDomain = "_email-verification." + normalizedDomain;
        log.info("Querying DNS TXT record for: {}", queryDomain);

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("java.naming.provider.url", "dns://8.8.8.8");

            DirContext ictx = new InitialDirContext(env);
            Attributes attrs = ictx.getAttributes(queryDomain, new String[]{"TXT"});

            if (attrs != null) {
                Attribute txtAttr = attrs.get("TXT");
                if (txtAttr != null) {
                    NamingEnumeration<?> e = txtAttr.getAll();
                    while (e.hasMore()) {
                        String txtVal = (String) e.next();
                        log.debug("Found TXT record for {}: {}", queryDomain, txtVal);
                        // Clean quotes if present
                        txtVal = txtVal.replace("\"", "").trim();
                        for (String part : txtVal.split(";")) {
                            String trimmed = part.trim();
                            if (trimmed.startsWith("iss=")) {
                                String issuer = trimmed.substring(4).trim();
                                log.info("DNS delegation resolved: {} -> iss={}", queryDomain, issuer);
                                return issuer;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("DNS query failed for {}: {}", queryDomain, e.getMessage());
        }

        return null;
    }

    private boolean isMockDomain(String domain) {
        if (mockSupportedDomains == null) return false;
        for (String mockDom : mockSupportedDomains) {
            if (domain.equalsIgnoreCase(mockDom.trim()) || domain.endsWith("." + mockDom.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the EVT `iss` claim matches the DNS delegation record.
     * EVT `iss` is a full HTTPS URL (e.g. "https://accounts.google.com" or "http://localhost:8080" in tests)
     * DNS record provides the host (e.g. "accounts.google.com" or "localhost:8080")
     */
    public boolean verifyIssuerMatchesDelegation(String evtIssClaim, String delegatedIssuerHost) {
        if (evtIssClaim == null || delegatedIssuerHost == null) {
            return false;
        }

        try {
            URI issUri = URI.create(evtIssClaim);
            String issHost = issUri.getHost();
            if (issUri.getPort() != -1 && issUri.getPort() != 80 && issUri.getPort() != 443) {
                issHost = issHost + ":" + issUri.getPort();
            }

            return delegatedIssuerHost.equalsIgnoreCase(issHost)
                    || delegatedIssuerHost.equalsIgnoreCase(issUri.getAuthority());
        } catch (Exception e) {
            log.warn("Failed to parse EVT iss URL: {}", evtIssClaim);
            return false;
        }
    }
}
