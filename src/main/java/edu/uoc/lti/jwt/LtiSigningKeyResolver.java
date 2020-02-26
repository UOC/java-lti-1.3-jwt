package edu.uoc.lti.jwt;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;

/**
 * @author xaracil@uoc.edu
 */
@Log
@RequiredArgsConstructor
public class LtiSigningKeyResolver extends SigningKeyResolverAdapter {
	private final String keysetUrl;

	@Override
	public Key resolveSigningKey(JwsHeader header, Claims claims) {
		String keyId = header.getKeyId();

		if (keyId == null) {
			return null;
		}

		Key key = null;
		try {
			JwkProvider provider = new UrlJwkProvider(new URL(keysetUrl));
			Jwk jwk = provider.get(keyId);
			key = jwk.getPublicKey();
		} catch (MalformedURLException | JwkException e) {
			log.warning("Signing key cannot be resolved: " + e.getMessage());
		}
		return key;
	}
}
