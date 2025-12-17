package com.security.auditor.model.entity;

/**
 * Detection Source Enumeration
 * Indicates whether vulnerability was found by static analysis or ML
 */
public enum DetectionSource {
    STATIC,
    ML,
    HYBRID
}
