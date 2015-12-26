package org.bsworks.misc.xrds;

import java.io.IOException;


/**
 * HTTP protocol returned {@code 4xx} or {@code 5xx} status code.
 *
 * @author Lev Himmelfarb
 */
public class HTTPErrorException
	extends IOException {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 1L;


	/**
	 * Create new exception.
	 *
	 * @param respCode HTTP response code.
	 * @param cause The original exception.
	 */
	HTTPErrorException(final int respCode, final IOException cause) {
		super("HTTP error " + respCode + ".", cause);
	}
}
