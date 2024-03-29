package edu.uoc.lti.jwt.claims;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.uoc.lti.claims.ClaimAccessor;
import edu.uoc.lti.claims.ClaimsEnum;
import edu.uoc.lti.jwt.LtiSigningKeyResolver;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * @author xaracil@uoc.edu
 */
public class JWSClaimAccessor implements ClaimAccessor {
	private final static long _5_MINUTES = 5 * 60;

	private ObjectMapper objectMapper = new ObjectMapper();

	private LtiSigningKeyResolver ltiSigningKeyResolver;

	private Jws<Claims> jws;

	long allowedClockSkewSeconds = _5_MINUTES;


	public JWSClaimAccessor(String keySetUrl) {
		this.ltiSigningKeyResolver = new LtiSigningKeyResolver(keySetUrl);
		objectMapper.configure(
						DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	}

	@Override
	public void decode(String token) {
		this.jws = Jwts.parserBuilder()
						.setSigningKeyResolver(ltiSigningKeyResolver)
						.setAllowedClockSkewSeconds(allowedClockSkewSeconds)
						.build()
						.parseClaimsJws(token);
	}

	@Override
	public String getKId() {
		if (this.jws == null) {
			return null;
		}

		return jws.getHeader().getKeyId();
	}

	@Override
	public String getIssuer() {
		if (this.jws == null) {
			return null;
		}

		return jws.getBody().getIssuer();
	}

	@Override
	public List<String> getAudiences() {
		if (this.jws == null) {
			return null;
		}

		String aud = jws.getBody().getAudience();
		aud.replaceAll("^\\[", "").replaceAll("\\]$", "");
		return Arrays.asList(aud.split(","));
	}

	@Override
	public String getSubject() {
		if (this.jws == null) {
			return null;
		}

		return jws.getBody().getSubject();
	}

	@Override
	public String getAzp() {
		return get(ClaimsEnum.AUTHORIZED_PART);
	}

	@Override
	public Date getIssuedAt() {
		if (this.jws == null) {
			return null;
		}

		return jws.getBody().getIssuedAt();
	}

	@Override
	public Date getExpiration() {
		if (this.jws == null) {
			return null;
		}

		return jws.getBody().getExpiration();
	}

	@Override
	public String get(ClaimsEnum claim) {
		if (this.jws == null) {
			return null;
		}

		return jws.getBody().get(claim.getName(), String.class);
	}

	@Override
	public <T> T get(ClaimsEnum claim, Class<T> returnClass) {
		if (jws == null ||jws.getBody() == null || !jws.getBody().containsKey(claim.getName())) {
			return null;
		}
		final Object o = jws.getBody().get(claim.getName());
		// doing this way because Jwts deserialize json classes as LinkedHashMap
		return objectMapper.convertValue(o, returnClass);
	}
}
