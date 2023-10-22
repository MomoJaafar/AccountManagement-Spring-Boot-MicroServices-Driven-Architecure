package com.appsdeveloperblog.photoapp.api.gateway;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

	@Autowired
	private Environment environment;

	public AuthorizationHeaderFilter() {
		super(Config.class);
	}

	public static class Config {
		// Put configuration properties here

	}

	@Override
	public GatewayFilter apply(Config config) {

		return (exchange, chain) -> {

			ServerHttpRequest request = exchange.getRequest();
			if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "No Authorization Header.", HttpStatus.UNAUTHORIZED);
			}

			String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authorizationHeader.replace("Bearer ", "");

			if (!isJwtValid(jwt, environment)) {
				return onError(exchange, "JWT token is not valid.", HttpStatus.UNAUTHORIZED);
			}
			return chain.filter(exchange);
		};
	}

	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		return response.setComplete();
	}

	/**
	 * 
	 * @param jwt
	 * @return
	 */
	private boolean isJwtValid(String jwt, Environment environment) {
		boolean returnValue = true;

		// Create the SecretKey object same way it was created for Authentication
		// process.
		String tokenSecret = environment.getProperty("token.sercet");
		byte[] secretKeyBytes = Base64.getEncoder().encode(tokenSecret.getBytes());
		SecretKey secretKey = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());

		String subject = null;
		try {
			subject = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt).getBody().getSubject();

		} catch (JwtException e) {
			return false;
		}

		if (subject == null || subject.isEmpty()) {
			returnValue = false;
		}
		return returnValue;
	}
}