package com.boylesoftware.catalina.authenticator.openid;

import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;


/**
 * Response handler for exctracting an HTTP response header value.
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
	public HeaderResponseContentHandler(String headerName) {

		this.headerName = headerName;
	}


	/* (non-Javadoc)
	 * @see com.boylesoftware.catalina.authenticator.openid.ResponseContentHandler#getContent(java.net.HttpURLConnection, java.io.ByteArrayOutputStream)
	 */
	@Override
	public String getContent(HttpURLConnection con,
			ByteArrayOutputStream respBuf) {

		return con.getHeaderField(this.headerName);
	}
}
