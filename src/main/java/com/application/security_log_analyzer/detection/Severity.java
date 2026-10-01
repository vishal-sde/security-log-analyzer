package com.application.security_log_analyzer.detection;

public enum Severity {
    LOW,MEDIUM,HIGH,CRITICAL;

    public static Severity fromScore(int score){
        if(score >= 70) return CRITICAL;
        if(score >= 50) return HIGH;
        if(score >= 30) return MEDIUM;
        return LOW;
    }

}
