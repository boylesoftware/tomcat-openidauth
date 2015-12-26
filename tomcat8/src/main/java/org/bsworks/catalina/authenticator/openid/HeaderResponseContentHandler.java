package org.bsworks.catalina.authenticator.openid;

import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;


/**
 * Response handler for extracting an HTTP response header value.
 *
 * @author Lev Himmelfarb
 */
class HeaderResponseContentHandler
	extends ResponseContentHandler<String> {

	/**
	 * The header name.
	 */
	private final String headerName;


	/**
	 * Create new handler.
	 *
	 * @param headerName The header name.
	 */
	HeaderResponseContentHandler(final String headerName) {

		this.headerName = headerName;
	}


	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	String getContent(final HttpURLConnection con,
			final ByteArrayOutputStream respBuf) {

		return con.getHeaderField(this.headerName);
	}
}
