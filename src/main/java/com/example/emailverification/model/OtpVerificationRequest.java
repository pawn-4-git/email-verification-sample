package com.example.emailverification.model;

public class OtpVerificationRequest {
    private String email;
    private String otpCode;

    public OtpVerificationRequest() {
    }

    public OtpVerificationRequest(String email, String otpCode) {
        this.email = email;
        this.otpCode = otpCode;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getOtpCode() {
        return otpCode;
    }

    public void setOtpCode(String otpCode) {
        this.otpCode = otpCode;
    }
}
