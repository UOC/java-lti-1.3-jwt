package edu.uoc.lti.jwt.client;

import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;

import java.security.SecureRandom;
import java.util.Date;

import edu.uoc.lti.clientcredentials.ClientCredentialsRequest;
import edu.uoc.lti.clientcredentials.ClientCredentialsTokenBuilder;
import edu.uoc.lti.jwt.AlgorithmFactory;

/**
 * @author Xavi Aracil <xaracil@uoc.edu>
 */
@RequiredArgsConstructor
public class JWSClientCredentialsTokenBuilder implements ClientCredentialsTokenBuilder {

	private final static long _5_MINUTES = 5 * 30 * 1000;
	private final String publicKey;
	private final String privateKey;

	private SecureRandom secureRandom = new SecureRandom();

	@Override
	public String build(ClientCredentialsRequest request) {
		AlgorithmFactory algorithmFactory = new AlgorithmFactory(publicKey, privateKey);
		byte bytes[] = new byte[10];
		secureRandom.nextBytes(bytes);
		return Jwts.builder()
						.setHeaderParam("kid", request.getKid())
						.setIssuer(request.getToolName())
						.setSubject(request.getClientId())
						.setAudience(request.getOauth2Url())
						.setIssuedAt(new Date())
						.setExpiration(new Date(System.currentTimeMillis() + _5_MINUTES))
						.signWith(algorithmFactory.getPrivateKey())
						.setId(new String(bytes))
						.compact();
	}
}
