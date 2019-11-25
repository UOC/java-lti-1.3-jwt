package edu.uoc.lti.jwt;

/**
 * @author Xavi Aracil <xaracil@uoc.edu>
 */
public class BadToolProviderConfigurationException extends RuntimeException {
	public BadToolProviderConfigurationException(String message) {
		super(message);
	}

	public BadToolProviderConfigurationException(Throwable cause) {
		super(cause);
	}
}
