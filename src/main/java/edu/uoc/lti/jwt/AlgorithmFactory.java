package edu.uoc.lti.jwt;

import lombok.Getter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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

	public AlgorithmFactory(String publicKey, String privateKey, String algorithm) {
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance(algorithm);
			byte[] encodedPb = Base64.getDecoder().decode(publicKey);
			X509EncodedKeySpec keySpecPb = new X509EncodedKeySpec(encodedPb);
			this.publicKey = (RSAPublicKey) kf.generatePublic(keySpecPb);

			ASN1InputStream derReader = new ASN1InputStream(Base64.getDecoder().decode(privateKey));

			ASN1Sequence seq = (ASN1Sequence) derReader.readObject();

			if (seq.size() < 9) {
				throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
			}

			// skip version seq.getObjectAt(0);
			BigInteger modulus = ((ASN1Integer) seq.getObjectAt(1)).getValue();
			BigInteger publicExp = ((ASN1Integer) seq.getObjectAt(2)).getValue();
			BigInteger privateExp = ((ASN1Integer) seq.getObjectAt(3)).getValue();
			BigInteger prime1 = ((ASN1Integer) seq.getObjectAt(4)).getValue();
			BigInteger prime2 = ((ASN1Integer) seq.getObjectAt(5)).getValue();
			BigInteger exp1 = ((ASN1Integer) seq.getObjectAt(6)).getValue();
			BigInteger exp2 = ((ASN1Integer) seq.getObjectAt(7)).getValue();
			BigInteger crtCoef = ((ASN1Integer) seq.getObjectAt(8)).getValue();

			RSAPrivateCrtKeySpec keySpecPv = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);

			this.privateKey = (RSAPrivateKey) kf.generatePrivate(keySpecPv);

		} catch (GeneralSecurityException | IOException e) {
			throw new BadToolProviderConfigurationException(e);
		}
	}
}
