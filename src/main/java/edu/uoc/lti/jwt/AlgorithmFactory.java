package edu.uoc.lti.jwt;

import lombok.Getter;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author xaracil@uoc.edu
 */
public class AlgorithmFactory {
	@Getter
	private final RSAPublicKey publicKey;
	@Getter
	private final RSAPrivateKey privateKey;

	public AlgorithmFactory(String publicKey, String privateKey) {
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
			byte[] encodedPb = Base64.getDecoder().decode(publicKey);
			X509EncodedKeySpec keySpecPb = new X509EncodedKeySpec(encodedPb);
			this.publicKey = (RSAPublicKey) kf.generatePublic(keySpecPb);

			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
			this.privateKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);

		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new BadToolProviderConfigurationException(e);
		}
	}
}
