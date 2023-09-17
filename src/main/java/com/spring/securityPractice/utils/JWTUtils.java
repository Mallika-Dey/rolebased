package com.spring.securityPractice.utils;

import com.spring.securityPractice.constants.AppConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JWTUtils {
	private static final Random RANDOM = new SecureRandom();
	private static final String ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	public static Boolean hasTokenExpired(String token) {
		Claims claims = Jwts.parser().setSigningKey(AppConstants.TOKEN_SECRET).parseClaimsJws(token).getBody();
		Date tokenExpirationDate = claims.getExpiration();
		Date today = new Date();
		return tokenExpirationDate.before(today);
	}

	public static String generateToken(String id, List<String> roles) {
		return Jwts.builder().setSubject(id).claim("role", roles)
				.setExpiration(new Date(System.currentTimeMillis() + AppConstants.EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS256, AppConstants.TOKEN_SECRET).compact();
	}

	public static String generateUserID(int length) {
		return generateRandomString(length);
	}

	private static String generateRandomString(int length) {
		StringBuilder returnValue = new StringBuilder(length);
		for (int i = 0; i < length; i++)
			returnValue.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
		return new String(returnValue);
	}

	public static String extractUser(String token) {
		return Jwts.parser().setSigningKey(AppConstants.TOKEN_SECRET).parseClaimsJws(token).getBody().getSubject();
	}

	public static List<GrantedAuthority> extractRoles(String token) {
		Claims claim = Jwts.parser().setSigningKey(AppConstants.TOKEN_SECRET).parseClaimsJws(token).getBody();

		List<String> roles = claim.get("role", List.class);
	
		if (roles != null) {
			return roles.stream()
					.map(role -> new SimpleGrantedAuthority(role.toUpperCase()))
					.collect(Collectors.toList());
		}

		return Collections.emptyList();
	}

}
