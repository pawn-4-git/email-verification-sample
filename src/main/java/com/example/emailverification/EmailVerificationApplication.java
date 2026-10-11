package com.example.emailverification;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class EmailVerificationApplication {

    public static void main(String[] args) {
        // Register Bouncy Castle Provider for full Ed25519 and cryptographic curve support
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        SpringApplication.run(EmailVerificationApplication.class, args);
    }
}
