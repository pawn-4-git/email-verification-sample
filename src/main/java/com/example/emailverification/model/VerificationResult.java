package com.example.emailverification.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VerificationResult {
    private boolean success;
    private boolean fallbackRequired;
    private String message;
    private String verifiedEmail;
    private List<VerificationAuditStep> auditLog = new ArrayList<>();
    private Map<String, Object> tokenClaims = new HashMap<>();

    public VerificationResult() {
    }

    public static VerificationResult success(String email, String message, List<VerificationAuditStep> auditLog, Map<String, Object> claims) {
        VerificationResult res = new VerificationResult();
        res.setSuccess(true);
        res.setFallbackRequired(false);
        res.setVerifiedEmail(email);
        res.setMessage(message);
        res.setAuditLog(auditLog);
        res.setTokenClaims(claims != null ? claims : new HashMap<>());
        return res;
    }

    public static VerificationResult fallback(String email, String message, List<VerificationAuditStep> auditLog) {
        VerificationResult res = new VerificationResult();
        res.setSuccess(false);
        res.setFallbackRequired(true);
        res.setVerifiedEmail(email);
        res.setMessage(message);
        res.setAuditLog(auditLog);
        return res;
    }

    public static VerificationResult failure(String email, String message, List<VerificationAuditStep> auditLog) {
        VerificationResult res = new VerificationResult();
        res.setSuccess(false);
        res.setFallbackRequired(false);
        res.setVerifiedEmail(email);
        res.setMessage(message);
        res.setAuditLog(auditLog);
        return res;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public boolean isFallbackRequired() {
        return fallbackRequired;
    }

    public void setFallbackRequired(boolean fallbackRequired) {
        this.fallbackRequired = fallbackRequired;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getVerifiedEmail() {
        return verifiedEmail;
    }

    public void setVerifiedEmail(String verifiedEmail) {
        this.verifiedEmail = verifiedEmail;
    }

    public List<VerificationAuditStep> getAuditLog() {
        return auditLog;
    }

    public void setAuditLog(List<VerificationAuditStep> auditLog) {
        this.auditLog = auditLog;
    }

    public Map<String, Object> getTokenClaims() {
        return tokenClaims;
    }

    public void setTokenClaims(Map<String, Object> tokenClaims) {
        this.tokenClaims = tokenClaims;
    }
}
