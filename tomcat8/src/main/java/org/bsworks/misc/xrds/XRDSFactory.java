package org.bsworks.misc.xrds;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.SAXException;


/**
 * XRDS factory used to discover, load and parse XRDS documents. Factory
 * instances are reusable and thread-safe.
 *
 * <p>The XRDS format and discovery logic is described in
 * <a href="http://docs.oasis-open.org/xri/2.0/specs/xri-resolution-V2.0.html">
 * Extensible Resource Identifier (XRI) Resolution Version 2.0</a>
 * specification.
 *
 * @author Lev Himmelfarb
 */
public class XRDSFactory {

	/**
	 * Default XRI proxy resolver.
	 */
	public static final String DEFAULT_XRI_PROXY = "http://xri.net/";

	/**
	 * Default HTTP connect timeout in milliseconds.
	 *
	 * @see #setHttpConnectTimeout
	 */
	public static final int DEFAULT_HTTP_CONNECT_TO = 5000;

	/**
	 * Default HTTP read timeout in milliseconds.
	 *
	 * @see #setHttpReadTimeout
	 */
	public static final int DEFAULT_HTTP_READ_TO = 5000;

	/**
	 * XRDS content type.
	 */
	private static final String XRDS_CONTENT_TYPE = "application/xrds+xml";

	/**
	 * XRD content type.
	 */
	private static final String XRD_CONTENT_TYPE = "application/xrd+xml";

	/**
	 * Host meta-data content type.
	 */
	private static final String HOSTMD_CONTENT_TYPE = "application/host-meta";

	/**
	 * HTML content type.
	 */
	private static final String HTML_CONTENT_TYPE = "text/html";

	/**
	 * XRDS location header name.
	 */
	private static final String XRDS_LOCATION_HEADER = "X-XRDS-Location";

	/**
	 * Pattern for extracting character encoding from the content type header.
	 */
	private static final Pattern CHARSET_HEADER_PATTERN =
		Pattern.compile("(?:^|;)\\s*charset\\s*=\\s*([^;\\s]+)");

	/**
	 * Pattern for finding XRDS location link in host meta-data.
	 */
	private static final Pattern XRDS_LOCATION_LINK_PATTERN = Pattern.compile(
		"^Link:\\s*<([^>]*)>.*;\\s*type=\"application/xrds\\+xml\".*$",
		Pattern.MULTILINE);

	/**
	 * Pattern for finding XRDS location meta tag in HTML.
	 */
	private static final Pattern XRDS_LOCATION_META_PATTERN = Pattern.compile(
		"<meta\\s[^>]*(?:" +
		"(?<=\\s)http-equiv=\"" + XRDS_LOCATION_HEADER + "\"" +
		"[^>]*(?<=\\s)content=\"([^\"]*)\"" +
		"|(?<=\\s)content=\"([^\"]*)\"" +
		"[^>]*(?<=\\s)http-equiv=\"" + XRDS_LOCATION_HEADER + "\")" +
		"[^>]*>", Pattern.CASE_INSENSITIVE);


	/**
	 * Buffer for accumulating HTTP response data.
	 */
	private static final class ResponseBuffer
		extends ByteArrayOutputStream {

		/**
		 * Create new buffer.
		 */
		ResponseBuffer() {
			super(4096);
		}


		/**
		 * Get input stream for the data accumulated in the buffer.
		 *
		 * @return Input stream for reading the response data.
		 */
		InputStream getInputStream() {

			return new ByteArrayInputStream(this.buf, 0, this.count);
		}
	}


	/**
	 * HTTP connect timeout.
	 */
	private int httpConnectTimeout = DEFAULT_HTTP_CONNECT_TO;

	/**
	 * HTTP read timeout.
	 */
	private int httpReadTimeout = DEFAULT_HTTP_READ_TO;

	/**
	 * SAX parser factory.
	 */
	private final SAXParserFactory parserFactory;

	/**
	 * URL of the XRI proxy resolver.
	 */
	private URL xriProxyURL;

	/**
	 * Debug logger.
	 */
	private final DebugLogger log;


	/**
	 * Create new parser.
	 *
	 * @param log Debug logger to use.
	 */
	public XRDSFactory(final DebugLogger log) {

		try {
			this.xriProxyURL = new URL(DEFAULT_XRI_PROXY);
		} catch (final MalformedURLException e) {
			// should not happen
			throw new Error(e);
		}
		this.log = log;

		this.parserFactory = SAXParserFactory.newInstance();
		this.parserFactory.setNamespaceAware(true);
	}


	/**
	 * Get XRI proxy resolver.
	 *
	 * @return The XRI proxy resolver URL.
	 */
	public String getXRIProxyURL() {

		return this.xriProxyURL.toString();
	}

	/**
	 * Set XRI proxy resolver. Default is {@value #DEFAULT_XRI_PROXY}.
	 *
	 * @param xriProxyURL The XRI proxy resolver URL.
	 *
	 * @throws MalformedURLException If the specified URL is invalid.
	 */
	public void setXRIProxyURL(final String xriProxyURL)
		throws MalformedURLException {

		this.xriProxyURL = new URL(xriProxyURL);
	}

	/**
	 * Get currently configured HTTP connect timeout.
	 *
	 * @return The timeout in milliseconds.
	 */
	public int getHttpConnectTimeout() {

		return this.httpConnectTimeout;
	}

	/**
	 * Set HTTP connect timeout. The default is
	 * {@link #DEFAULT_HTTP_CONNECT_TO}.
	 *
	 * @param httpConnectTimeout The timeout in milliseconds.
	 *
	 * @see URLConnection#setConnectTimeout
	 */
	public void setHttpConnectTimeout(final int httpConnectTimeout) {

		this.httpConnectTimeout = httpConnectTimeout;
	}

	/**
	 * Get currently configured HTTP read timeout.
	 *
	 * @return The timeout in milliseconds.
	 */
	public int getHttpReadTimeout() {

		return this.httpReadTimeout;
	}

	/**
	 * Set HTTP read timeout. The default is {@link #DEFAULT_HTTP_READ_TO}.
	 *
	 * @param httpReadTimeout The timeout in milliseconds.
	 *
	 * @see URLConnection#setReadTimeout
	 */
	public void setHttpReadTimeout(final int httpReadTimeout) {

		this.httpReadTimeout = httpReadTimeout;
	}


	/**
	 * Resolve an XRI in to an XRD using the configured XRI proxy resolver.
	 *
	 * @param xri The XRI to resolve.
	 * @param serviceType Required SEP type.
	 *
	 * @return The resulting XRD, or {@code null} if there was no XRD in the
	 * response or if the XRD status is not success.
	 *
	 * @throws SAXException If an error happened parsing the response.
	 * @throws IOException If an I/O error happens communicating with the
	 * resolution proxy.
	 * @throws MalformedURLException If could not build the XRI resolution proxy
	 * call URL, which most likely means that the specified XRI or/and service
	 * type is invalid.
	 */
	public XRD resolveXRI(final String xri, final String serviceType)
		throws SAXException, IOException, MalformedURLException {

		final boolean debug = this.log.isEnabled();

		// build XRI resolution proxy call URL
		final URL callURL = new URL(this.xriProxyURL,
				xri + "?_xrd_r=" + XRD_CONTENT_TYPE +
					";sep=true;uric=true&_xrd_t=" +
					serviceType);

		// allocate buffers
		final byte[] buf = new byte[512];
		try (final ResponseBuffer respBuf = new ResponseBuffer()) {

			// get response
			if (debug)
				this.log.log("resolving XRI [" + xri + "] using " + callURL);
			final HttpURLConnection con =
				(HttpURLConnection) callURL.openConnection();
			con.setConnectTimeout(this.httpConnectTimeout);
			con.setReadTimeout(this.httpReadTimeout);
			con.addRequestProperty("Accept", XRD_CONTENT_TYPE);
			final String contentType = this.readContent(con, buf, respBuf);

			// check response content type
			if (!XRD_CONTENT_TYPE.equals(contentType))
				throw new IOException("Unexpected XRD content type: " +
						contentType);

			// parse the XRD
			final XRD xrd = this.parse(respBuf.getInputStream());

			// check the XRD
			if ((xrd == null) || (xrd.getStatusCode() != XRD.SC_SUCCESS))
				return null;

			// return the XRD
			return xrd;
		}
	}

	/**
	 * Discover an XRDS document using an HTTP(S) URL.
	 *
	 * @param url The URL.
	 *
	 * @return The discovery result, or {@code null} if the URL could not be
	 * used for discovery.
	 *
	 * @throws HTTPErrorException If HTTP fails communicating with the servers.
	 * @throws IOException If an unexpected I/O error happens communicating with
	 * the servers.
	 * @throws SAXException If an error happens parsing the XRDS.
	 */
	public XRDSHTTPDiscoveryResult discover(final URL url)
		throws IOException, SAXException {

		final boolean debug = this.log.isEnabled();

		// allocate buffers
		final byte[] buf = new byte[512];
		try (final ResponseBuffer respBuf = new ResponseBuffer()) {

			// attempt HEAD protocol and process redirects
			URL lastURL = url;
			HttpURLConnection con;
			String contentType;
			do {
				if (debug)
					this.log.log("attempting HEAD protocol at " + lastURL);
				con = (HttpURLConnection) lastURL.openConnection();
				con.setConnectTimeout(this.httpConnectTimeout);
				con.setReadTimeout(this.httpReadTimeout);
				con.addRequestProperty("Accept", XRDS_CONTENT_TYPE + ", " +
						HOSTMD_CONTENT_TYPE + ";q=0.8, " +
						HTML_CONTENT_TYPE + ";q=0.5");
				con.setRequestMethod("HEAD");
				con.setInstanceFollowRedirects(false);
				contentType = this.readContent(con, buf, respBuf);
				int respCode = con.getResponseCode();
				if ((respCode == 301) || (respCode == 302) || (respCode == 303)
						|| (respCode == 307)) {
					if (debug)
						this.log.log("response is a redirect");
					lastURL = new URL(con.getHeaderField("Location"));
				} else {
					break;
				}
			} while (true);

			// process HEAD response and determine the XRDS URL
			URL xrdsURL = null;
			String xrdsLocation = con.getHeaderField(XRDS_LOCATION_HEADER);
			if (xrdsLocation != null) {

				xrdsURL = new URL(xrdsLocation);

			} else if (XRDS_CONTENT_TYPE.equals(contentType)) {

				xrdsURL = lastURL;

			} else if (HOSTMD_CONTENT_TYPE.equals(contentType)) {

				// extract XRDS location from host meta-data
				if (debug)
					this.log.log("getting host meta-data from " + lastURL);
				con = (HttpURLConnection) lastURL.openConnection();
				con.setConnectTimeout(this.httpConnectTimeout);
				con.setReadTimeout(this.httpReadTimeout);
				con.addRequestProperty("Accept", HOSTMD_CONTENT_TYPE);
				contentType = this.readContent(con, buf, respBuf);
				final String md = respBuf.toString(
						this.getContentCharset(con, "UTF-8"));
				final Matcher m = XRDS_LOCATION_LINK_PATTERN.matcher(md);
				if (m.find())
					xrdsURL = new URL(xrdsLocation = m.group(1));

			} else if (HTML_CONTENT_TYPE.equals(contentType)) {

				// extract XRDS location from HTML response
				if (debug)
					this.log.log("getting HTML from " + lastURL);
				con = (HttpURLConnection) lastURL.openConnection();
				con.setConnectTimeout(this.httpConnectTimeout);
				con.setReadTimeout(this.httpReadTimeout);
				con.addRequestProperty("Accept", HTML_CONTENT_TYPE);
				contentType = this.readContent(con, buf, respBuf);
				final String html = respBuf.toString(
						this.getContentCharset(con, "UTF-8"));
				final Matcher m = XRDS_LOCATION_META_PATTERN.matcher(html);
				if (m.find()) {
					xrdsLocation = m.group(1);
					if (xrdsLocation == null)
						xrdsLocation = m.group(2);
					xrdsURL = new URL(xrdsLocation);
				}
			}

			// got XRDS URL?
			if (xrdsURL == null) {

				// get response body
				if ("HEAD".equals(con.getRequestMethod())) {
					if (debug)
						this.log.log("getting content from " + lastURL);
					con = (HttpURLConnection) lastURL.openConnection();
					con.setConnectTimeout(this.httpConnectTimeout);
					con.setReadTimeout(this.httpReadTimeout);
					contentType = this.readContent(con, buf, respBuf);
				}

				// return result with no XRD
				if (debug)
					this.log.log("the URL did not resolve to XRDS, returning " +
							contentType + " response");
				return new XRDSHTTPDiscoveryResult(null, lastURL, contentType,
						this.getContentCharset(con, null), respBuf);
			}

			// get the XRDS using GET protocol
			if (debug)
				this.log.log("getting XRDS from " + xrdsURL);
			con = (HttpURLConnection) xrdsURL.openConnection();
			con.setConnectTimeout(this.httpConnectTimeout);
			con.setReadTimeout(this.httpReadTimeout);
			con.addRequestProperty("Accept", XRDS_CONTENT_TYPE);
			contentType = this.readContent(con, buf, respBuf);
			if (!XRDS_CONTENT_TYPE.equals(contentType))
				throw new IOException("Unexpected XRDS content type: " +
						contentType);

			// parse the XRDS and return the result
			final XRD xrd = this.parse(respBuf.getInputStream());
			return new XRDSHTTPDiscoveryResult(xrd, xrdsURL, contentType,
					this.getContentCharset(con, null), respBuf);
		}
	}

	/**
	 * Parse XRDS document.
	 *
	 * @param xrdsIn Input stream with the XRDS document. The method
	 * automatically closes the input stream before return (including in case of
	 * an exception).
	 *
	 * @return Final XRD from the parsed XRDS, or {@code null} if no XRDs found.
	 *
	 * @throws SAXException If an error happens parsing the XRDS.
	 * @throws IOException If an I/O error happens reading the XRDS input
	 * stream.
	 */
	public XRD parse(final InputStream xrdsIn)
		throws SAXException, IOException {

		try {
			final SAXParser parser = this.parserFactory.newSAXParser();

			final XRDSParserHandler handler = new XRDSParserHandler();
			parser.parse(xrdsIn, handler);

			return handler.getXRD();

		} catch (ParserConfigurationException e) {
			throw new RuntimeException("Error creating SAX parser.", e);
		} finally {
			xrdsIn.close();
		}
	}


	/**
	 * Read HTTP response.
	 *
	 * @param con HTTP connection.
	 * @param buf Buffer to use to read the response.
	 * @param respBuf Buffer, to which to write the response content. The buffer
	 * is emptied automatically before use.
	 *
	 * @return Content type, or {@code null}.
	 *
	 * @throws HTTPErrorException If HTTP fails.
	 * @throws IOException If an I/O error happens reading the response.
	 */
	private String readContent(final HttpURLConnection con, final byte[] buf,
			final ResponseBuffer respBuf)
		throws HTTPErrorException, IOException {

		final boolean debug = this.log.isEnabled();

		respBuf.reset();

		try {

			try (final InputStream in = con.getInputStream()) {
				int n;
				while ((n = in.read(buf)) >= 0)
					respBuf.write(buf, 0, n);
			}

		} catch (final IOException e) {
			final int respCode = con.getResponseCode();
			if (debug)
				this.log.log("HTTP error " + respCode + ": " + e.getMessage(),
						e);

			@SuppressWarnings("resource")
			InputStream es = con.getErrorStream();
			if (es != null) {
				try {
					respBuf.reset();
					int n;
					while ((n = es.read(buf)) >= 0)
						respBuf.write(buf, 0, n);
				} finally {
					es.close();
				}
				if (debug)
					this.log.log("error response content:\n" +
							respBuf.toString("UTF-8"));
			}

			if (respCode >= 400)
				throw new HTTPErrorException(respCode, e);

			throw e;
		}

		if (debug) {
			this.log.log("HTTP response " + con.getResponseCode() +
					", headers:\n" + this.getResponseHeadersString(con));

			if (respBuf.size() > 0) {
				final String charset = this.getContentCharset(con, "UTF-8");
				this.log.log("response content (" + charset + "):\n" +
					respBuf.toString(charset));
			}
		}

		String contentType = con.getContentType();
		if (contentType != null) {
			final int semiInd = contentType.indexOf(';');
			if (semiInd > 0)
				contentType = contentType.substring(0, semiInd);
		}

		return contentType;
	}

	/**
	 * Get HTTP response headers as a string for debug logging.
	 *
	 * @param con The HTTP connection.
	 *
	 * @return The headers.
	 */
	private String getResponseHeadersString(final HttpURLConnection con) {

		final StringBuilder res = new StringBuilder(512);
		int i = 0;
		String val;
		do {
			final String name = con.getHeaderFieldKey(i);
			val = con.getHeaderField(i);
			if (val != null) {
				if (res.length() > 0)
					res.append('\n');
				if (name != null)
					res.append(name).append(": ");
				res.append(val);
			}
			i++;
		} while (val != null);

		return res.toString();
	}

	/**
	 * Determine HTTP response content character set from the content type
	 * header.
	 *
	 * @param con The HTTP connection.
	 * @param defaultCharset Default character set to return if no character set
	 * information is in the response headers. Can be {@code null}.
	 *
	 * @return Character set for the content.
	 */
	private String getContentCharset(final HttpURLConnection con,
			final String defaultCharset) {

		final String contentType = con.getContentType();
		if (contentType != null) {
			final Matcher m = CHARSET_HEADER_PATTERN.matcher(contentType);
			if (m.find())
				return m.group(1);
		}

		return defaultCharset;
	}
}
