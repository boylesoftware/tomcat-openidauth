package org.bsworks.misc.xrds;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;


/**
 * Result of XRDS discovery from an HTTP(S) URL.
 *
 * @author Lev Himmelfarb
 */
public class XRDSHTTPDiscoveryResult {

	/**
	 * Final XRD.
	 */
	private final XRD finalXRD;

	/**
	 * URL of the last request.
	 */
	private final URL lastRequestURL;

	/**
	 * Last response content type.
	 */
	private final String responseContentType;

	/**
	 * Last response content encoding.
	 */
	private final String responseContentCharset;

	/**
	 * Buffer with the last response content.
	 */
	private final ByteArrayOutputStream responseBuffer;


	/**
	 * Create new result object.
	 *
	 * @param finalXRD Final XRD, or {@code null} if no XRD in the response.
	 * @param lastRequestURL The last request URL.
	 * @param responseContentType Last response content type, or {@code null} if
	 * content type was not in the response headers.
	 * @param responseContentCharset Last response content character set, or
	 * {@code null} if that information was not in the response headers.
	 * @param responseBuffer Buffer with the last response content.
	 */
	XRDSHTTPDiscoveryResult(final XRD finalXRD, final URL lastRequestURL,
			final String responseContentType,
			final String responseContentCharset,
			final ByteArrayOutputStream responseBuffer) {

		this.finalXRD = finalXRD;
		this.lastRequestURL = lastRequestURL;
		this.responseContentType = responseContentType;
		this.responseContentCharset = responseContentCharset;
		this.responseBuffer = responseBuffer;
	}


	/**
	 * Get final XRD.
	 *
	 * @return The XRD, or {@code null} if no XRD in the response.
	 */
	public XRD getFinalXRD() {

		return this.finalXRD;
	}

	/**
	 * Get URL of the last request made during the discovery.
	 *
	 * @return The last request URL.
	 */
	public URL getLastRequestURL() {

		return this.lastRequestURL;
	}

	/**
	 * Get content type of the last response in the discovery sequence.
	 *
	 * @return The content type, or {@code null} if content type was not in the
	 * response headers.
	 */
	public String getLastResponseContentType() {

		return this.responseContentType;
	}

	/**
	 * Get content of the last response in the discovery sequence.
	 *
	 * @return The content of the response as string.
	 *
	 * @throws UnsupportedEncodingException If the character set in the response
	 * headers was invalid.
	 */
	public String getLastResponseContent()
		throws UnsupportedEncodingException {

		return this.responseBuffer.toString(
				this.responseContentCharset != null ?
						this.responseContentCharset : "UTF-8");
	}
}
