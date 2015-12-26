package org.bsworks.catalina.authenticator.openid;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;


/**
 * Handler for OpenID direct communication response.
 *
 * @author Lev Himmelfarb
 */
class OpenIDDirectResponseContentHandler
	extends ResponseContentHandler<Map<String, String>> {

	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	Map<String, String> getContent(final HttpURLConnection con,
			final ByteArrayOutputStream respBuf)
		throws IOException {

		final Map<String, String> res = new HashMap<>();
		try (final BufferedReader in = new BufferedReader(
				new InputStreamReader(
						new ByteArrayInputStream(respBuf.toByteArray()),
						"UTF-8"))) {
			String line;
			while ((line = in.readLine()) != null) {
				final int colonInd = line.indexOf(':');
				res.put(line.substring(0, colonInd),
						line.substring(colonInd + 1));
			}
		}

		return res;
	}
}
