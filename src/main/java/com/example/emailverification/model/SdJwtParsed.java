package com.example.emailverification.model;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.List;

public class SdJwtParsed {
    private String rawToken;
    private String issuerEvtJwtString;
    private SignedJWT issuerEvtSignedJwt;
    private JWSHeader evtHeader;
    private JWTClaimsSet evtClaims;

    private List<String> disclosures;

    private String keyBindingJwtString;
    private SignedJWT keyBindingSignedJwt;
    private JWSHeader kbHeader;
    private JWTClaimsSet kbClaims;

    public SdJwtParsed() {
    }

    public String getRawToken() {
        return rawToken;
    }

    public void setRawToken(String rawToken) {
        this.rawToken = rawToken;
    }

    public String getIssuerEvtJwtString() {
        return issuerEvtJwtString;
    }

    public void setIssuerEvtJwtString(String issuerEvtJwtString) {
        this.issuerEvtJwtString = issuerEvtJwtString;
    }

    public SignedJWT getIssuerEvtSignedJwt() {
        return issuerEvtSignedJwt;
    }

    public void setIssuerEvtSignedJwt(SignedJWT issuerEvtSignedJwt) {
        this.issuerEvtSignedJwt = issuerEvtSignedJwt;
    }

    public JWSHeader getEvtHeader() {
        return evtHeader;
    }

    public void setEvtHeader(JWSHeader evtHeader) {
        this.evtHeader = evtHeader;
    }

    public JWTClaimsSet getEvtClaims() {
        return evtClaims;
    }

    public void setEvtClaims(JWTClaimsSet evtClaims) {
        this.evtClaims = evtClaims;
    }

    public List<String> getDisclosures() {
        return disclosures;
    }

    public void setDisclosures(List<String> disclosures) {
        this.disclosures = disclosures;
    }

    public String getKeyBindingJwtString() {
        return keyBindingJwtString;
    }

    public void setKeyBindingJwtString(String keyBindingJwtString) {
        this.keyBindingJwtString = keyBindingJwtString;
    }

    public SignedJWT getKeyBindingSignedJwt() {
        return keyBindingSignedJwt;
    }

    public void setKeyBindingSignedJwt(SignedJWT keyBindingSignedJwt) {
        this.keyBindingSignedJwt = keyBindingSignedJwt;
    }

    public JWSHeader getKbHeader() {
        return kbHeader;
    }

    public void setKbHeader(JWSHeader kbHeader) {
        this.kbHeader = kbHeader;
    }

    public JWTClaimsSet getKbClaims() {
        return kbClaims;
    }

    public void setKbClaims(JWTClaimsSet kbClaims) {
        this.kbClaims = kbClaims;
    }
}
