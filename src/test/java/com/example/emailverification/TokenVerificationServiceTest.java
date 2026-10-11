package com.example.emailverification;

import com.example.emailverification.model.VerificationResult;
import com.example.emailverification.service.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class TokenVerificationServiceTest {

    @Autowired
    private TokenVerificationService tokenVerificationService;

    @Autowired
    private MockIssuerService mockIssuerService;

    @Autowired
    private OtpService otpService;

    private final String testEmail = "demo@example.com";
    private final String testNonce = "test-session-nonce-12345";
    private final String testAud = "http://localhost:8080";

    @BeforeEach
    void setUp() {
        mockIssuerService.init();
    }

    @Test
    @DisplayName("RFC 9901 SD-JWT+KB トークンの完全検証 (kid あり)")
    void testVerifyTokenWithKid() throws Exception {
        String token = mockIssuerService.generateSampleToken(testEmail, testNonce, testAud, true);
        assertNotNull(token);
        assertTrue(token.contains("~"));

        VerificationResult result = tokenVerificationService.verify(testEmail, token, testNonce);
        assertTrue(result.isSuccess(), "検証が成功すること: " + result.getMessage());
        assertFalse(result.isFallbackRequired());
        assertEquals(testEmail, result.getVerifiedEmail());
        assertNotNull(result.getTokenClaims());
        assertTrue(result.getAuditLog().stream().allMatch(step -> step.isPassed()), "全監査ステップが合格すること");
    }

    @Test
    @DisplayName("2026年10月更新: kid が省略されたトークン (Gmailスタイル) の候補鍵ループによる検証成功")
    void testVerifyTokenWithoutKid() throws Exception {
        // includeKid = false ensures EVT header has no kid claim
        String token = mockIssuerService.generateSampleToken(testEmail, testNonce, testAud, false);
        assertNotNull(token);

        VerificationResult result = tokenVerificationService.verify(testEmail, token, testNonce);
        assertTrue(result.isSuccess(), "kid省略トークンでもJWKS候補鍵ループにより検証が成功すること: " + result.getMessage());
        assertFalse(result.isFallbackRequired());
    }

    @Test
    @DisplayName("トークン未入力時のOTPフォールバックフローへの移行")
    void testFallbackToOtpWhenTokenEmpty() {
        VerificationResult result = tokenVerificationService.verify(testEmail, "", testNonce);
        assertFalse(result.isSuccess());
        assertTrue(result.isFallbackRequired(), "フォールバックフラグが立つこと");

        String generatedOtp = otpService.getLatestOtpForTesting(testEmail);
        assertNotNull(generatedOtp, "フォールバック用OTPが発行されていること");
        assertTrue(otpService.verifyOtp(testEmail, generatedOtp), "発行されたOTPで検証できること");
    }

    @Test
    @DisplayName("メールアドレス不一致時のエラー検出")
    void testEmailMismatch() throws Exception {
        String token = mockIssuerService.generateSampleToken("alice@example.com", testNonce, testAud, true);
        VerificationResult result = tokenVerificationService.verify("bob@example.com", token, testNonce);

        assertFalse(result.isSuccess());
        assertTrue(result.getMessage().contains("メールアドレスが一致しません"));
    }

    @Test
    @DisplayName("セッションノンス不一致時のエラー検出")
    void testNonceMismatch() throws Exception {
        String token = mockIssuerService.generateSampleToken(testEmail, "different-nonce", testAud, true);
        VerificationResult result = tokenVerificationService.verify(testEmail, token, testNonce);

        assertFalse(result.isSuccess());
        assertTrue(result.getMessage().contains("ノンス"));
    }

    @Test
    @DisplayName("改ざんされたトークンの署名エラー検出")
    void testTamperedToken() throws Exception {
        String token = mockIssuerService.generateSampleToken(testEmail, testNonce, testAud, true);
        // Tamper with the payload of EVT
        String[] parts = token.split("~");
        String tamperedEvt = parts[0].substring(0, parts[0].length() - 5) + "AAAAA";
        String tamperedToken = tamperedEvt + "~" + parts[1];

        VerificationResult result = tokenVerificationService.verify(testEmail, tamperedToken, testNonce);
        assertFalse(result.isSuccess());
    }
}
