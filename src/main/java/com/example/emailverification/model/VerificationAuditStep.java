package com.example.emailverification.model;

public class VerificationAuditStep {
    private String stepNumber;
    private String title;
    private boolean passed;
    private String details;

    public VerificationAuditStep() {
    }

    public VerificationAuditStep(String stepNumber, String title, boolean passed, String details) {
        this.stepNumber = stepNumber;
        this.title = title;
        this.passed = passed;
        this.details = details;
    }

    public String getStepNumber() {
        return stepNumber;
    }

    public void setStepNumber(String stepNumber) {
        this.stepNumber = stepNumber;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public boolean isPassed() {
        return passed;
    }

    public void setPassed(boolean passed) {
        this.passed = passed;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }
}
