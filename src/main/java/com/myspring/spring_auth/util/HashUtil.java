package com.myspring.spring_auth.util;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;

public final class HashUtil {
    private HashUtil() {
    }

    public static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash input", e);
        }
    }
}
