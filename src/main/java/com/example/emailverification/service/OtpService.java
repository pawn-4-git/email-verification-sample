package com.example.emailverification.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OtpService {
    private static final Logger log = LoggerFactory.getLogger(OtpService.class);

    private final SecureRandom random = new SecureRandom();

    public static class OtpRecord {
        private final String code;
        private final Instant expiresAt;

        public OtpRecord(String code, Instant expiresAt) {
            this.code = code;
            this.expiresAt = expiresAt;
        }

        public String getCode() {
            return code;
        }

        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    // Map email -> OtpRecord
    private final Map<String, OtpRecord> otpStore = new ConcurrentHashMap<>();

    /**
     * Generate a 6-digit fallback OTP code valid for 10 minutes
     */
    public String generateOtp(String email) {
        String normalizedEmail = email.trim().toLowerCase();
        int codeInt = 100000 + random.nextInt(900000);
        String code = String.valueOf(codeInt);

        Instant expiresAt = Instant.now().plusSeconds(600);
        otpStore.put(normalizedEmail, new OtpRecord(code, expiresAt));

        log.info("Generated fallback OTP for [{}]: {} (valid for 10 min)", normalizedEmail, code);
        return code;
    }

    /**
     * Verify submitted OTP code
     */
    public boolean verifyOtp(String email, String submittedCode) {
        if (email == null || submittedCode == null) return false;
        String normalizedEmail = email.trim().toLowerCase();

        OtpRecord record = otpStore.get(normalizedEmail);
        if (record == null) {
            log.warn("No OTP found for {}", normalizedEmail);
            return false;
        }

        if (record.isExpired()) {
            log.warn("OTP for {} has expired", normalizedEmail);
            otpStore.remove(normalizedEmail);
            return false;
        }

        boolean valid = record.getCode().equals(submittedCode.trim());
        if (valid) {
            log.info("OTP verification successful for {}", normalizedEmail);
            otpStore.remove(normalizedEmail);
        } else {
            log.warn("Invalid OTP submitted for {}", normalizedEmail);
        }
        return valid;
    }

    public String getLatestOtpForTesting(String email) {
        if (email == null) return null;
        OtpRecord rec = otpStore.get(email.trim().toLowerCase());
        return (rec != null && !rec.isExpired()) ? rec.getCode() : null;
    }
}
