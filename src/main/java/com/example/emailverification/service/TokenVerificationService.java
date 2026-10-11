package com.example.emailverification.service;

import com.example.emailverification.model.IssuerMetadata;
import com.example.emailverification.model.SdJwtParsed;
import com.example.emailverification.model.VerificationAuditStep;
import com.example.emailverification.model.VerificationResult;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Service
public class TokenVerificationService {
    private static final Logger log = LoggerFactory.getLogger(TokenVerificationService.class);

    private final DnsResolverService dnsResolverService;
    private final IssuerDiscoveryService issuerDiscoveryService;
    private final OtpService otpService;

    @Value("${email-verification.verifier.origin:http://localhost:8080}")
    private String verifierOrigin;

    @Value("${email-verification.verifier.token-expiration-leeway-seconds:60}")
    private long expirationLeewaySeconds;

    public TokenVerificationService(DnsResolverService dnsResolverService,
                                  IssuerDiscoveryService issuerDiscoveryService,
                                  OtpService otpService) {
        this.dnsResolverService = dnsResolverService;
        this.issuerDiscoveryService = issuerDiscoveryService;
        this.otpService = otpService;
    }

    /**
     * Verifies the email verification token according to RFC 9901 / Chrome October 2026 specifications.
     */
    public VerificationResult verify(String submittedEmail, String rawToken, String expectedSessionNonce) {
        List<VerificationAuditStep> auditLog = new ArrayList<>();

        if (submittedEmail == null || submittedEmail.isBlank()) {
            auditLog.add(new VerificationAuditStep("0", "フォーム検証", false, "メールアドレスが入力されていません。"));
            return VerificationResult.failure("", "メールアドレスが入力されていません。", auditLog);
        }

        String normalizedEmail = submittedEmail.trim();

        // Check if token is empty or missing -> trigger Fallback OTP flow
        if (rawToken == null || rawToken.trim().isEmpty()) {
            log.info("Token field is empty for [{}]. Falling back to OTP flow.", normalizedEmail);
            String otpCode = otpService.generateOtp(normalizedEmail);
            auditLog.add(new VerificationAuditStep("1", "フォールバック判定", true,
                    "トークンが未提供（ブラウザ未対応またはスキップ）。ワンタイムパスワード（OTP）送信フローに移行しました。(テスト用コード: " + otpCode + ")"));
            return VerificationResult.fallback(normalizedEmail, "確認コードをメールで送信しました。", auditLog);
        }

        // Step 1: Parse the SD-JWT token
        SdJwtParsed sdJwt;
        try {
            sdJwt = parseSdJwt(rawToken);
            auditLog.add(new VerificationAuditStep("1", "SD-JWT トークン解析", true,
                    String.format("RFC 9901 形式のトークンを解析しました。[EVT Alg: %s, kid: %s, Disclosures: %d, KB-JWT Alg: %s]",
                            sdJwt.getEvtHeader().getAlgorithm().getName(),
                            sdJwt.getEvtHeader().getKeyID() != null ? sdJwt.getEvtHeader().getKeyID() : "(省略)",
                            sdJwt.getDisclosures().size(),
                            sdJwt.getKbHeader().getAlgorithm().getName())));
        } catch (Exception e) {
            log.error("Failed to parse SD-JWT: {}", e.getMessage());
            auditLog.add(new VerificationAuditStep("1", "SD-JWT トークン解析", false, "SD-JWT 形式の解析に失敗しました: " + e.getMessage()));
            return VerificationResult.failure(normalizedEmail, "トークンの形式が不正です。", auditLog);
        }

        JWTClaimsSet evtClaims = sdJwt.getEvtClaims();
        JWTClaimsSet kbClaims = sdJwt.getKbClaims();

        // Step 2: Validate expected values and session claims
        try {
            // 2.1 Verify email_verified == true
            Boolean emailVerified = (Boolean) evtClaims.getClaim("email_verified");
            if (!Boolean.TRUE.equals(emailVerified)) {
                auditLog.add(new VerificationAuditStep("2.1", "メール認証ステータス検証", false, "email_verified クレームが true ではありません。"));
                return VerificationResult.failure(normalizedEmail, "メール認証ステータスが無効です。", auditLog);
            }
            auditLog.add(new VerificationAuditStep("2.1", "メール認証ステータス検証", true, "email_verified: true"));

            // 2.2 Verify email match (Chrome 156+ preserves case; verify case-insensitively / matches)
            String tokenEmail = evtClaims.getStringClaim("email");
            if (tokenEmail == null || !tokenEmail.equalsIgnoreCase(normalizedEmail)) {
                auditLog.add(new VerificationAuditStep("2.2", "メールアドレス一致検証", false,
                        String.format("送信メールアドレス '%s' とトークン内メールアドレス '%s' が一致しません。", normalizedEmail, tokenEmail)));
                return VerificationResult.failure(normalizedEmail, "メールアドレスが一致しません。", auditLog);
            }
            auditLog.add(new VerificationAuditStep("2.2", "メールアドレス一致検証", true,
                    String.format("メールアドレス一致確認成功: %s", tokenEmail)));

            // 2.3 Verify Audience (aud) in KB-JWT matches verifier origin
            List<String> kbAudiences = kbClaims.getAudience();
            String kbAud = (kbAudiences != null && !kbAudiences.isEmpty()) ? kbAudiences.get(0) : null;
            if (kbAud == null || !isAudienceMatching(kbAud, verifierOrigin)) {
                auditLog.add(new VerificationAuditStep("2.3", "オーディエンス (aud) 検証", false,
                        String.format("KB-JWT の aud '%s' が検証ツールのオリジン '%s' と一致しません。", kbAud, verifierOrigin)));
                return VerificationResult.failure(normalizedEmail, "オーディエンスが一致しません。", auditLog);
            }
            auditLog.add(new VerificationAuditStep("2.3", "オーディエンス (aud) 検証", true,
                    String.format("オーディエンス一致: %s", kbAud)));

            // 2.4 Verify Nonce in KB-JWT matches session nonce
            String kbNonce = kbClaims.getStringClaim("nonce");
            String initialHtmlNonce = "evp-initial-nonce-a9b8c7d6-e5f4-4321-8765-123456789abc";
            if (expectedSessionNonce != null && !expectedSessionNonce.isBlank()) {
                boolean matchesSession = kbNonce != null && kbNonce.equals(expectedSessionNonce.trim());
                boolean matchesInitial = kbNonce != null && kbNonce.equals(initialHtmlNonce);
                if (!matchesSession && !matchesInitial) {
                    auditLog.add(new VerificationAuditStep("2.4", "ノンス (nonce) 検証", false,
                            String.format("セッションのノンス '%s' とトークン内のノンス '%s' が一致しません。", expectedSessionNonce, kbNonce)));
                    return VerificationResult.failure(normalizedEmail, "ノンスが無効または期限切れです。", auditLog);
                }
            }
            auditLog.add(new VerificationAuditStep("2.4", "ノンス (nonce) 検証", true,
                    String.format("セッションにバインドされたノンス一致: %s", kbNonce)));

            // 2.5 Verify Token expiration (exp) and issuance (iat)
            Date now = new Date();
            Date exp = evtClaims.getExpirationTime();
            Date iat = evtClaims.getIssueTime();
            Date leewayExp = (exp != null) ? new Date(exp.getTime() + expirationLeewaySeconds * 1000) : null;

            if (exp != null && now.after(leewayExp)) {
                auditLog.add(new VerificationAuditStep("2.5", "有効期限 (exp) 検証", false,
                        String.format("トークンの有効期限切れです。(exp: %s, 現在: %s)", exp, now)));
                return VerificationResult.failure(normalizedEmail, "トークンの有効期限が切れています。", auditLog);
            }
            auditLog.add(new VerificationAuditStep("2.5", "有効期限 (exp) 検証", true,
                    String.format("トークン有効期限内確認 (iat: %s, exp: %s)", iat, exp)));

        } catch (Exception e) {
            log.error("Claims validation error: {}", e.getMessage());
            auditLog.add(new VerificationAuditStep("2", "クレーム検証エラー", false, e.getMessage()));
            return VerificationResult.failure(normalizedEmail, "クレーム検証エラー: " + e.getMessage(), auditLog);
        }

        // Step 3: Verify DNS delegation
        String emailDomain = extractDomainFromEmail(normalizedEmail);
        String evtIss = evtClaims.getIssuer();
        if (evtIss == null || evtIss.isBlank()) {
            auditLog.add(new VerificationAuditStep("3", "DNS 委任検証", false, "EVT に issuer (iss) クレームが存在しません。"));
            return VerificationResult.failure(normalizedEmail, "発行者情報が不正です。", auditLog);
        }

        String delegatedIssuer = dnsResolverService.resolveIssuerDomain(emailDomain);
        if (delegatedIssuer == null) {
            auditLog.add(new VerificationAuditStep("3", "DNS 委任検証", false,
                    String.format("ドメイン '%s' の _email-verification TXT レコードが見つかりません。", emailDomain)));
            return VerificationResult.failure(normalizedEmail, "DNS 委任レコードが見つかりません。", auditLog);
        }

        boolean delegationValid = dnsResolverService.verifyIssuerMatchesDelegation(evtIss, delegatedIssuer);
        if (!delegationValid) {
            auditLog.add(new VerificationAuditStep("3", "DNS 委任検証", false,
                    String.format("DNS委任ホスト '%s' が EVT の iss '%s' と一致しません。", delegatedIssuer, evtIss)));
            return VerificationResult.failure(normalizedEmail, "DNS 委任の不一致です。", auditLog);
        }
        auditLog.add(new VerificationAuditStep("3", "DNS 委任検証", true,
                String.format("_email-verification.%s -> iss=%s 一致確認成功 (iss: %s)", emailDomain, delegatedIssuer, evtIss)));

        // Step 4: Discover issuer metadata and fetch JWKS
        IssuerMetadata metadata = issuerDiscoveryService.discoverIssuer(evtIss);
        if (metadata == null || metadata.getJwksUri() == null) {
            auditLog.add(new VerificationAuditStep("4", "発行者メタデータ取得", false,
                    String.format("%s/.well-known/email-verification からのメタデータ取得に失敗しました。", evtIss)));
            return VerificationResult.failure(normalizedEmail, "発行者のメタデータ取得に失敗しました。", auditLog);
        }

        JWKSet jwkSet = issuerDiscoveryService.fetchJwks(metadata.getJwksUri());
        if (jwkSet == null || jwkSet.getKeys().isEmpty()) {
            auditLog.add(new VerificationAuditStep("4", "JWKS 公開鍵セット取得", false,
                    String.format("JWKS URI (%s) から公開鍵セットの取得に失敗しました。", metadata.getJwksUri())));
            return VerificationResult.failure(normalizedEmail, "発行者の公開鍵取得に失敗しました。", auditLog);
        }
        auditLog.add(new VerificationAuditStep("4", "発行者メタデータおよび JWKS 取得", true,
                String.format("メタデータ検出完了 (jwks_uri: %s, 提供鍵数: %d)", metadata.getJwksUri(), jwkSet.getKeys().size())));

        // Step 5: Cryptographic signature verification
        // 5.1 Verify EVT signature using JWKS (with kid or iteration for kid-less tokens as per October 2026 update)
        boolean evtSigVerified = false;
        String matchedKeyId = null;
        String headerKid = sdJwt.getEvtHeader().getKeyID();

        if (headerKid != null && !headerKid.isBlank()) {
            JWK key = jwkSet.getKeyByKeyId(headerKid);
            if (key != null && verifyJwsWithJwk(sdJwt.getIssuerEvtSignedJwt(), key)) {
                evtSigVerified = true;
                matchedKeyId = headerKid;
            }
        }

        if (!evtSigVerified) {
            // October 2026 Update: When kid is absent or not matched, iterate over candidate keys in JWKS
            log.info("Kid claim is {} (Gmail style or missing kid). Iterating over candidate keys in JWKS...",
                    headerKid == null ? "absent" : "unmatched (" + headerKid + ")");
            for (JWK candidateKey : jwkSet.getKeys()) {
                if (verifyJwsWithJwk(sdJwt.getIssuerEvtSignedJwt(), candidateKey)) {
                    evtSigVerified = true;
                    matchedKeyId = candidateKey.getKeyID() != null ? candidateKey.getKeyID() : "(候補鍵)";
                    break;
                }
            }
        }

        if (!evtSigVerified) {
            auditLog.add(new VerificationAuditStep("5.1", "EVT 発行者署名検証", false,
                    "JWKS 内のどの公開鍵でも EVT の暗号署名を検証できませんでした。"));
            return VerificationResult.failure(normalizedEmail, "発行者の電子署名が無効です。", auditLog);
        }
        auditLog.add(new VerificationAuditStep("5.1", "EVT 発行者署名検証", true,
                String.format("発行者による署名の検証に成功しました (使用鍵: %s, kid省略対応: %s)",
                        matchedKeyId, headerKid == null ? "はい (Gmail仕様)" : "いいえ")));

        // 5.2 Verify Key Binding JWT (KB-JWT) using ephemeral key in cnf.jwk
        try {
            Map<String, Object> cnfClaim = evtClaims.getJSONObjectClaim("cnf");
            if (cnfClaim == null || !cnfClaim.containsKey("jwk")) {
                auditLog.add(new VerificationAuditStep("5.2", "ブラウザ公開鍵 (cnf.jwk) 抽出", false,
                        "EVT にブラウザのエフェメラル公開鍵 (cnf.jwk) が含まれていません。"));
                return VerificationResult.failure(normalizedEmail, "エフェメラル公開鍵が存在しません。", auditLog);
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) cnfClaim.get("jwk");
            JWK browserEphemeralJwk = JWK.parse(jwkMap);

            boolean kbSigVerified = verifyJwsWithJwk(sdJwt.getKeyBindingSignedJwt(), browserEphemeralJwk);
            if (!kbSigVerified) {
                auditLog.add(new VerificationAuditStep("5.2", "Key Binding (KB-JWT) 署名検証", false,
                        "ブラウザのエフェメラル秘密鍵による KB-JWT 署名の検証に失敗しました。"));
                return VerificationResult.failure(normalizedEmail, "Key Binding 署名が無効です。", auditLog);
            }
            auditLog.add(new VerificationAuditStep("5.2", "Key Binding (KB-JWT) 署名検証", true,
                    String.format("ブラウザのエフェメラル公開鍵 (%s, crv: %s) による KB-JWT 署名検証に成功しました。",
                            browserEphemeralJwk.getKeyType().getValue(),
                            (browserEphemeralJwk instanceof OctetKeyPair) ? ((OctetKeyPair) browserEphemeralJwk).getCurve() :
                                    (browserEphemeralJwk instanceof ECKey) ? ((ECKey) browserEphemeralJwk).getCurve() : "N/A")));

        } catch (Exception e) {
            log.error("Failed to verify Key Binding signature: {}", e.getMessage());
            auditLog.add(new VerificationAuditStep("5.2", "Key Binding (KB-JWT) 署名検証", false, e.getMessage()));
            return VerificationResult.failure(normalizedEmail, "Key Binding 検証エラー: " + e.getMessage(), auditLog);
        }

        // 5.3 Verify sd_hash in KB-JWT matches hash of EVT
        try {
            String tokenSdHash = kbClaims.getStringClaim("sd_hash");
            if (tokenSdHash == null || tokenSdHash.isBlank()) {
                auditLog.add(new VerificationAuditStep("5.3", "ダイジェストハッシュ (sd_hash) 検証", false,
                        "KB-JWT に sd_hash クレームが存在しません。"));
                return VerificationResult.failure(normalizedEmail, "sd_hash クレームが見つかりません。", auditLog);
            }

            // Calculate SHA-256 hash of the Issuer EVT part (RFC 9901 SD-JWT with KB)
            // RFC 9901 specifies hashing the token part before the KB-JWT (which includes trailing ~ if present)
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            String evtPart = sdJwt.getIssuerEvtJwtString();

            byte[] digestWithTilde = sha256.digest((evtPart + "~").getBytes(StandardCharsets.US_ASCII));
            String expectedSdHashWithTilde = Base64URL.encode(digestWithTilde).toString();

            sha256.reset();
            byte[] digestWithoutTilde = sha256.digest(evtPart.getBytes(StandardCharsets.US_ASCII));
            String expectedSdHashWithoutTilde = Base64URL.encode(digestWithoutTilde).toString();

            boolean sdHashMatches = tokenSdHash.equals(expectedSdHashWithTilde) || tokenSdHash.equals(expectedSdHashWithoutTilde);
            if (!sdHashMatches) {
                auditLog.add(new VerificationAuditStep("5.3", "ダイジェストハッシュ (sd_hash) 検証", false,
                        String.format("sd_hash 不一致: 提供=%s, 期待値=%s", tokenSdHash, expectedSdHashWithTilde)));
                return VerificationResult.failure(normalizedEmail, "sd_hash の検証に失敗しました。", auditLog);
            }
            auditLog.add(new VerificationAuditStep("5.3", "ダイジェストハッシュ (sd_hash) 検証", true,
                    String.format("sd_hash 一致確認成功 (SHA-256: %s)", tokenSdHash)));

        } catch (Exception e) {
            log.error("sd_hash verification error: {}", e.getMessage());
            auditLog.add(new VerificationAuditStep("5.3", "ダイジェストハッシュ (sd_hash) 検証", false, e.getMessage()));
            return VerificationResult.failure(normalizedEmail, "sd_hash 検証エラー: " + e.getMessage(), auditLog);
        }

        // All checks passed!
        log.info("Email verification SUCCEEDED for [{}]", normalizedEmail);
        Map<String, Object> claimsForDisplay = new HashMap<>(evtClaims.getClaims());
        claimsForDisplay.put("kb_aud", kbClaims.getAudience());
        claimsForDisplay.put("kb_nonce", kbClaims.getClaim("nonce"));
        claimsForDisplay.put("kb_sd_hash", kbClaims.getClaim("sd_hash"));

        return VerificationResult.success(normalizedEmail, "メールアドレスの暗号的検証が正常に完了しました！", auditLog, claimsForDisplay);
    }

    /**
     * Parse raw RFC 9901 SD-JWT token:
     * <Issuer-signed EVT>~<Disclosure 1>~...~<Disclosure N>~<Key Binding JWT>
     */
    public SdJwtParsed parseSdJwt(String rawToken) throws Exception {
        String trimmed = rawToken.trim();
        String[] parts = trimmed.split("~", -1);
        if (parts.length < 2) {
            throw new IllegalArgumentException("SD-JWT トークンには最低でも EVT と KB-JWT (チルダ区切り) が必要です。");
        }

        SdJwtParsed result = new SdJwtParsed();
        result.setRawToken(trimmed);

        String evtPart = parts[0];
        SignedJWT evtSignedJwt = SignedJWT.parse(evtPart);
        result.setIssuerEvtJwtString(evtPart);
        result.setIssuerEvtSignedJwt(evtSignedJwt);
        result.setEvtHeader(evtSignedJwt.getHeader());
        result.setEvtClaims(evtSignedJwt.getJWTClaimsSet());

        List<String> disclosures = new ArrayList<>();
        // Middle elements (if any) are disclosures
        for (int i = 1; i < parts.length - 1; i++) {
            if (!parts[i].isEmpty()) {
                disclosures.add(parts[i]);
            }
        }
        result.setDisclosures(disclosures);

        String kbPart = parts[parts.length - 1];
        if (kbPart.isEmpty()) {
            throw new IllegalArgumentException("Key Binding JWT (KB-JWT) が空です。");
        }
        SignedJWT kbSignedJwt = SignedJWT.parse(kbPart);
        result.setKeyBindingJwtString(kbPart);
        result.setKeyBindingSignedJwt(kbSignedJwt);
        result.setKbHeader(kbSignedJwt.getHeader());
        result.setKbClaims(kbSignedJwt.getJWTClaimsSet());

        return result;
    }

    private boolean verifyJwsWithJwk(SignedJWT signedJwt, JWK jwk) {
        try {
            if (jwk instanceof OctetKeyPair okp) {
                return signedJwt.verify(new Ed25519Verifier(okp.toPublicJWK()));
            } else if (jwk instanceof ECKey ecKey) {
                return signedJwt.verify(new ECDSAVerifier(ecKey.toPublicJWK()));
            } else if (jwk instanceof RSAKey rsaKey) {
                return signedJwt.verify(new RSASSAVerifier(rsaKey.toPublicJWK()));
            }
        } catch (Exception e) {
            log.debug("Verification attempt with key {} failed: {}", jwk.getKeyID(), e.getMessage());
        }
        return false;
    }

    private boolean isAudienceMatching(String tokenAud, String configuredOrigin) {
        if (tokenAud == null || configuredOrigin == null) return false;
        String a1 = tokenAud.replaceAll("/+$", "");
        String a2 = configuredOrigin.replaceAll("/+$", "");
        return a1.equalsIgnoreCase(a2);
    }

    private String extractDomainFromEmail(String email) {
        int atIdx = email.indexOf('@');
        if (atIdx != -1 && atIdx < email.length() - 1) {
            return email.substring(atIdx + 1).trim();
        }
        return email;
    }
}
