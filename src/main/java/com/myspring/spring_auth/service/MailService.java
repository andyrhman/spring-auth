package com.myspring.spring_auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import jakarta.mail.internet.MimeMessage;

@Service
public class MailService {
    private final JavaMailSender mailSender;
    private final String from;
    private final String appHost;

    public MailService(JavaMailSender mailSender,
            @Value("${spring.mail.from}") String from,
            @Value("${app.host}") String appHost) {
        this.mailSender = mailSender;
        this.from = from;
        this.appHost = appHost;
    }

    public void sendPasswordReset(String toEmail, String token) throws Exception {
        String url = String.format("%s/reset/%s", appHost, token);
        String html = buildForgotHtml(toEmail, url);

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setFrom(from);
        helper.setTo(toEmail);
        helper.setSubject("Reset your password");
        helper.setText(html, true);

        mailSender.send(message);
    }

    private String buildForgotHtml(String email, String url) throws Exception {
        // Minimal templating. Replace with Thymeleaf/FreeMarker if you prefer.
        String template;
        try (var is = new ClassPathResource("templates/forgot.html").getInputStream()) {
            template = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        // template should contain placeholders {{email}} and {{url}}
        return template.replace("{{email}}", htmlEscape(email)).replace("{{url}}", htmlEscape(url));
    }

    private String htmlEscape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
