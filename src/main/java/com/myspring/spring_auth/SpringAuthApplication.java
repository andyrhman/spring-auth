package com.myspring.spring_auth;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringAuthApplication {
	public static void main(String[] args) {
		Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

		if (dotenv.get("SPRING_DATASOURCE_URL") != null) {
			System.setProperty("SPRING_DATASOURCE_URL", dotenv.get("SPRING_DATASOURCE_URL"));
		}
		if (dotenv.get("SPRING_DATASOURCE_USERNAME") != null) {
			System.setProperty("SPRING_DATASOURCE_USERNAME", dotenv.get("SPRING_DATASOURCE_USERNAME"));
		}
		if (dotenv.get("SPRING_DATASOURCE_PASSWORD") != null) {
			System.setProperty("SPRING_DATASOURCE_PASSWORD", dotenv.get("SPRING_DATASOURCE_PASSWORD"));
		}
		if (dotenv.get("APP_JWT_SECRET") != null) {
			System.setProperty("APP_JWT_SECRET", dotenv.get("APP_JWT_SECRET"));
		}
		if (dotenv.get("SMTP_HOST") != null) {
			System.setProperty("SMTP_HOST", dotenv.get("SMTP_HOST"));
		}
		if (dotenv.get("SMTP_PORT") != null) {
			System.setProperty("SMTP_PORT", dotenv.get("SMTP_PORT"));
		}
		if (dotenv.get("SMTP_USER") != null) {
			System.setProperty("SMTP_USER", dotenv.get("SMTP_USER"));
		}
		if (dotenv.get("SMTP_PASSWORD") != null) {
			System.setProperty("SMTP_PASSWORD", dotenv.get("SMTP_PASSWORD"));
		}
		if (dotenv.get("APP_HOST") != null) {
			System.setProperty("APP_HOST", dotenv.get("APP_HOST"));
		}

		SpringApplication.run(SpringAuthApplication.class, args);
	}
}
