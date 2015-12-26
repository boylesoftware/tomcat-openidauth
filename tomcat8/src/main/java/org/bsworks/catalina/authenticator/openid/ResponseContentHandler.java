package org.bsworks.catalina.authenticator.openid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * HTTP response content handler.
 *
 * @author Lev Himmelfarb
 *
 * @param <T> Type of the object created from the response.
 */
abstract class ResponseContentHandler<T> {

	/**
	 * Pattern for extracting character encoding from the content type header.
	 */
	private static final Pattern CHARSET_HEADER_PATTERN =
		Pattern.compile("(?:^|;)\\s*charset\\s*=\\s*([^;\\s]+)");


	/**
	 * Process content and build the response object.
	 *
	 * @param con Used HTTP URL connection.
	 * @param respBuf Buffer with the response bytes.
	 *
	 * @return The response object.
	 *
	 * @throws IOException If an I/O error happens.
	 */
	abstract T getContent(HttpURLConnection con, ByteArrayOutputStream respBuf)
		throws IOException;

	/**
	 * Get string representation of the content that can be used for debugging.
	 * The default implementation creates a string from the bytes in the
	 * response buffer using either encoding from the HTTP response content type
	 * or UTF-8 if not specified in the response.
	 *
	 * @param con Used HTTP URL connection.
	 * @param respBuf Buffer with the response bytes.
	 *
	 * @return String representation of the response.
	 *
	 * @throws IOException If an I/O error happens.
	 */
	String getContentString(final HttpURLConnection con,
			final ByteArrayOutputStream respBuf)
		throws IOException {

		String enc = null;
		final String contentType = con.getContentType();
		if (contentType != null) {
			Matcher m = CHARSET_HEADER_PATTERN.matcher(contentType);
			if (m.find())
				enc = m.group(1);
		}
		if (enc == null)
			enc = "UTF-8";

		return respBuf.toString(enc);
	}
}
