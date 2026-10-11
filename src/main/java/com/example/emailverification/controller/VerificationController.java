package com.example.emailverification.controller;

import com.example.emailverification.model.OtpVerificationRequest;
import com.example.emailverification.model.VerificationRequest;
import com.example.emailverification.model.VerificationResult;
import com.example.emailverification.service.OtpService;
import com.example.emailverification.service.TokenVerificationService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class VerificationController {
    private static final Logger log = LoggerFactory.getLogger(VerificationController.class);

    private final TokenVerificationService tokenVerificationService;
    private final OtpService otpService;

    @Value("${email-verification.verifier.origin:http://localhost:8080}")
    private String verifierOrigin;

    @Value("${email-verification.origin-trial-token:}")
    private String originTrialToken;

    public VerificationController(TokenVerificationService tokenVerificationService, OtpService otpService) {
        this.tokenVerificationService = tokenVerificationService;
        this.otpService = otpService;
    }

    /**
     * Returns session-bound nonce and origin configuration for the verifier form
     */
    @GetMapping("/session-info")
    public ResponseEntity<Map<String, String>> getSessionInfo(HttpSession session) {
        String nonce = (String) session.getAttribute("EMAIL_VERIFICATION_NONCE");
        if (nonce == null) {
            nonce = UUID.randomUUID().toString();
            session.setAttribute("EMAIL_VERIFICATION_NONCE", nonce);
        }
        return ResponseEntity.ok(Map.of(
                "nonce", nonce,
                "verifierOrigin", verifierOrigin,
                "originTrialToken", originTrialToken
        ));
    }

    /**
     * Resets/refreshes the session nonce
     */
    @PostMapping("/session-info/refresh")
    public ResponseEntity<Map<String, String>> refreshSessionNonce(HttpSession session) {
        String newNonce = UUID.randomUUID().toString();
        session.setAttribute("EMAIL_VERIFICATION_NONCE", newNonce);
        return ResponseEntity.ok(Map.of("nonce", newNonce));
    }

    /**
     * Verify submitted email and EVT token
     */
    @PostMapping("/verify")
    public ResponseEntity<VerificationResult> verifyEmail(
            @RequestBody VerificationRequest request,
            HttpSession session) {
        String sessionNonce = (String) session.getAttribute("EMAIL_VERIFICATION_NONCE");
        log.info("Received verification request for email: [{}], token length: {}, sessionNonce: {}",
                request.getEmail(),
                request.getToken() != null ? request.getToken().length() : 0,
                sessionNonce);

        VerificationResult result = tokenVerificationService.verify(
                request.getEmail(),
                request.getToken(),
                sessionNonce
        );

        return ResponseEntity.ok(result);
    }

    /**
     * Verify fallback OTP code
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, Object>> verifyOtp(@RequestBody OtpVerificationRequest request) {
        boolean valid = otpService.verifyOtp(request.getEmail(), request.getOtpCode());
        if (valid) {
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "ワンタイムパスワードの認証に成功しました！"
            ));
        } else {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "入力された確認コードが無効か、期限切れです。"
            ));
        }
    }
}
