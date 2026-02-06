package com.myspring.spring_auth.controller;

import com.myspring.spring_auth.entity.User;
import com.myspring.spring_auth.repository.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.client.j2se.MatrixToImageWriter;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class QrController {

    private final UserRepository userRepo;

    public QrController(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    // ! WARNING: do not expose this publicly in production with real secrets in URLs.
    @GetMapping(value = "/qr", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> qrFromQuery(
            @RequestParam("secret") String base32Secret,
            @RequestParam("account") String account,
            @RequestParam(value = "issuer", defaultValue = "SpringAuth") String issuer) throws Exception {
        String otpAuth = buildOtpAuthUrl(issuer, account, base32Secret);
        byte[] png = generateQrPng(otpAuth, 350, 350);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.IMAGE_PNG_VALUE)
                .body(png);
    }

    @GetMapping(value = "/qr/{userId}", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> qrFromUser(@PathVariable String userId) throws Exception {
        UUID id = UUID.fromString(userId);
        Optional<User> uOpt = userRepo.findById(id);
        if (uOpt.isEmpty() || uOpt.get().getTfaSecret() == null || uOpt.get().getTfaSecret().isBlank()) {
            return ResponseEntity.notFound().build();
        }
        User u = uOpt.get();
        String otpAuth = buildOtpAuthUrl("MyApp", u.getUsername(), u.getTfaSecret());
        byte[] png = generateQrPng(otpAuth, 350, 350);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.IMAGE_PNG_VALUE)
                .body(png);
    }

    private static String buildOtpAuthUrl(String issuer, String accountName, String base32Secret) {
        // URL-encode fields prudently for production; kept simple here
        String encIssuer = urlEncode(issuer);
        String encAccount = urlEncode(accountName);
        return String.format(Locale.ROOT,
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                encIssuer, encAccount, base32Secret, encIssuer);
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    private static byte[] generateQrPng(String contents, int width, int height) throws Exception {
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(contents, BarcodeFormat.QR_CODE, width, height);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            MatrixToImageWriter.writeToStream(matrix, "PNG", baos);
            return baos.toByteArray();
        }
    }
}
