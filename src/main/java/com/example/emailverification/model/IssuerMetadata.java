package com.example.emailverification.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class IssuerMetadata {
    @JsonProperty("issuance_endpoint")
    private String issuanceEndpoint;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("signing_alg_values_supported")
    private List<String> signingAlgValuesSupported;

    public IssuerMetadata() {
    }

    public IssuerMetadata(String issuanceEndpoint, String jwksUri, List<String> signingAlgValuesSupported) {
        this.issuanceEndpoint = issuanceEndpoint;
        this.jwksUri = jwksUri;
        this.signingAlgValuesSupported = signingAlgValuesSupported;
    }

    public String getIssuanceEndpoint() {
        return issuanceEndpoint;
    }

    public void setIssuanceEndpoint(String issuanceEndpoint) {
        this.issuanceEndpoint = issuanceEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public List<String> getSigningAlgValuesSupported() {
        return signingAlgValuesSupported;
    }

    public void setSigningAlgValuesSupported(List<String> signingAlgValuesSupported) {
        this.signingAlgValuesSupported = signingAlgValuesSupported;
    }
}
