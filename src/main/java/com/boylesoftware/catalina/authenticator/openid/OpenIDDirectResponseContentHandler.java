package com.boylesoftware.catalina.authenticator.openid;

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
	 * @see com.boylesoftware.catalina.authenticator.openid.ResponseContentHandler#getContent(java.net.HttpURLConnection, java.io.ByteArrayOutputStream)
	 */
	@Override
	public Map<String, String> getContent(HttpURLConnection con,
			ByteArrayOutputStream respBuf)
		throws IOException {

		Map<String, String> res = new HashMap<String, String>();
		BufferedReader in = new BufferedReader(
				new InputStreamReader(
						new ByteArrayInputStream(respBuf.toByteArray()),
						"UTF-8"));
		try {
			String line;
			while ((line = in.readLine()) != null) {
				int colonInd = line.indexOf(':');
				res.put(line.substring(0, colonInd),
						line.substring(colonInd + 1));
			}
		} finally {
			in.close();
		}

		return res;
	}
}
