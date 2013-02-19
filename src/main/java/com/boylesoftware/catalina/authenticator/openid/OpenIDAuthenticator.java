package com.boylesoftware.catalina.authenticator.openid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.xml.sax.SAXException;

import com.boylesoftware.misc.xrds.DebugLogger;
import com.boylesoftware.misc.xrds.HTTPErrorException;
import com.boylesoftware.misc.xrds.SEP;
import com.boylesoftware.misc.xrds.XRD;
import com.boylesoftware.misc.xrds.XRDSFactory;
import com.boylesoftware.misc.xrds.XRDSHTTPDiscoveryResult;


/**
 * OpenID 2.0 authenticator implementation.
 *
 * @author Lev Himmelfarb
 */
public class OpenIDAuthenticator
	extends FormAuthenticator {

	/**
	 * Descriptive information about the authenticator implementation.
	 */
	private static final String INFO =
		(OpenIDAuthenticator.class).getName() + "/1.0";

	/**
	 * Show development mode mock login page URI suffix.
	 */
	private static final String MOCK_LOGIN_ACTION_URI =
		"/j_security_mock_login";

	/**
	 * Name of session note used to store the fact that this is an OpenID
	 * authentication (as opposed to regular form authentication).
	 */
	private static final String OPENID_AUTH_NOTE =
		(OpenIDAuthenticator.class).getName() + ".OPENID_AUTH";

	/**
	 * Name of request parameter used with request authentication action that
	 * specifies the OpenID user-supplied identifier.
	 */
	private static final String OPENID_ID_PARAM = "openid_identifier";

	/**
	 * Pattern for the mock login page template parameters.
	 */
	private static final Pattern TMPL_PARAM_PATTERN =
		Pattern.compile("\\$\\{([^}]+)\\}");

	/**
	 * OpenID namespace URI.
	 */
	private static final String OPENID_NS = "http://specs.openid.net/auth/2.0";

	/**
	 * XRI pattern.
	 */
	private static final Pattern XRI_PATTERN =
		Pattern.compile("^(?:xri://)?([=@+$!(].*)$");

	/**
	 * HTML content type.
	 */
	private static final String HTML_CONTENT_TYPE = "text/html";

	/**
	 * Plain text content type.
	 */
	private static final String TEXT_PLAIN_CONTENT_TYPE = "text/plain";

	/**
	 * Valid relationships for XRDS links in host meta-data.
	 */
	private static final Set<String> XRDS_LINK_RELS;
	static {
		XRDS_LINK_RELS = new HashSet<String>(1);
		XRDS_LINK_RELS.add(
			"describedby http://reltype.google.com/openid/xrd-op");
	}

	/**
	 * XRD server service type.
	 */
	private static final String XRD_SERVER_SERVICE_TYPE =
		"http://specs.openid.net/auth/2.0/server";

	/**
	 * XRD signon service type.
	 */
	private static final String XRD_SIGNON_SERVICE_TYPE =
		"http://specs.openid.net/auth/2.0/signon";

	/**
	 * XRD attribute exchange service type.
	 */
	private static final String XRD_AX_SERVICE_TYPE =
		"http://openid.net/srv/ax/1.0";

	/**
	 * Default AX attribute names by attribute types.
	 */
	private static final Map<String, String> AX_ATT_NAMES;
	static {
		AX_ATT_NAMES = new HashMap<String, String>(3);
		AX_ATT_NAMES.put("http://axschema.org/contact/email", "email");
		AX_ATT_NAMES.put("http://schema.openid.net/contact/email", "email");
		AX_ATT_NAMES.put("http://openid.net/schema/contact/internet/email",
				"email");
	}

	/**
	 * Pattern used to remove comments from HTML.
	 */
	private static final Pattern HTML_REMOVE_COMMENTS_PATTERN =
		Pattern.compile("<!--.*?-->", Pattern.DOTALL);

	/**
	 * Pattern used to extract HTML head section.
	 */
	private static final Pattern HTML_EXTRACT_HEAD_PATTERN =
		Pattern.compile("^.*<head(?:\\s[^>]*)?>(.*)</head\\s*>.*$",
				Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

	/**
	 * Pattern used to find OpenID links from HTML.
	 */
	private static final Pattern HTML_FIND_OP2_LINKS_PATTERN =
		Pattern.compile("<link\\s[^>]*(?:" +
				"(?<=\\s)rel=\"(openid2.provider|openid2.local_id)\"" +
				"[^>]*(?<=\\s)href=\"([^\"]*)\"" +
				"|(?<=\\s)href=\"([^\"]*)\"" +
				"[^>]*(?<=\\s)rel=\"(openid2.provider|openid2.local_id)\")" +
				"[^>]*>",
				Pattern.CASE_INSENSITIVE | Pattern.DOTALL);


	/**
	 * Result of parsing HTML for OpenID links.
	 */
	private static final class OpenIDHTMLParseResult {

		/**
		 * Extracted OP end-point URL.
		 */
		public URL opURL;

		/**
		 * Extracted local ID.
		 */
		public String localId;


		/**
		 * Public constructor.
		 */
		public OpenIDHTMLParseResult() { /* nothing */ }
	}


	/**
	 * The log.
	 */
	private final Log log = LogFactory.getLog(this.getClass());

	/**
	 * XRDS parser.
	 */
	private final XRDSFactory xrdsFactory;

	/**
	 * Redirect response content handler.
	 */
	private final ResponseContentHandler<String> redirectContentHandler =
		new HeaderResponseContentHandler("Location");

	/**
	 * OpenID direct response content handler.
	 */
	private final ResponseContentHandler<Map<String, String>>
	oidRespContentHandler =
		new OpenIDDirectResponseContentHandler();

	/**
	 * Base URL for the virtual host.
	 */
	private String hostBaseURI;

	/**
	 * URL of the single OpenID provider.
	 */
	private URI singleProviderURI;

	/**
	 * Allowed claimed ID pattern.
	 */
	private Pattern allowedClaimedIDPattern;

	/**
	 * OpenID Attribute Exchange extension attribute type of the attribute used
	 * as the login name with the realm.
	 */
	private String loginNameAttributeType;

	/**
	 * OpenID Attribute Exchange extension attribute name of the attribute used
	 * as the login name with the realm.
	 */
	private String loginNameAttributeName = "loginName";

	/**
	 * HTTP connect timeout.
	 */
	private int httpConnectTimeout = XRDSFactory.DEFAULT_HTTP_CONNECT_TO;

	/**
	 * HTTP read timeout.
	 */
	private int httpReadTimeout = XRDSFactory.DEFAULT_HTTP_READ_TO;

	/**
	 * Let user's browser to submit the request authentication form.
	 */
	private boolean browserRedirect = true;

	/**
	 * Tells if the authenticator is in development mode.
	 */
	private boolean developmentMode;


	/**
	 * Create new authenticator.
	 */
	public OpenIDAuthenticator() {

		final Log log = this.log;
		this.xrdsFactory = new XRDSFactory(new DebugLogger() {

			@Override
			public void log(String message, Throwable throwable) {
				log.debug(message, throwable);
			}

			@Override
			public void log(String message) {
				log.debug(message);
			}

			@Override
			public boolean isEnabled() {
				return log.isDebugEnabled();
			}
		});
	}


	/**
	 * Get URL of the XRI proxy resolver.
	 *
	 * @return The XRI proxy resolver URL.
	 */
	public String getXRIProxyURL() {

		return this.xrdsFactory.getXRIProxyURL().toString();
	}

	/**
	 * Set URL of the XRI proxy resolver. The default is
	 * {@link XRDSFactory#DEFAULT_XRI_PROXY}.
	 *
	 * @param xriProxyURL The XRI proxy resolver URL.
	 *
	 * @throws MalformedURLException If the URL is invalid.
	 */
	public void setXRIProxyURL(String xriProxyURL)
		throws MalformedURLException {

		this.xrdsFactory.setXRIProxyURL(xriProxyURL);
	}

	/**
	 * Get base URI for the virtual host.
	 *
	 * @return Host base URI.
	 */
	public String getHostBaseURI() {

		return this.hostBaseURI;
	}

	/**
	 * Set base URI for the virtual host. The URI is used when constructing
	 * return URLs for the web-application. If not set, the authenticator will
	 * attempt to construct it.
	 *
	 * @param hostBaseURI Host base URI. Must not end with a "/". Should be an
	 * HTTPS URI.
	 */
	public void setHostBaseURI(String hostBaseURI) {

		this.hostBaseURI = hostBaseURI;
	}

	/**
	 * Get URI of the single OpenID provider.
	 *
	 * @return Provider URI (a.k.a. OP Identifier).
	 */
	public String getSingleProviderURI() {

		if (this.singleProviderURI == null)
			return null;

		return this.singleProviderURI.toString();
	}

	/**
	 * Set URI of the single OpenID provider. When set, the authenticator never
	 * displays the configured login page, but instead immediately sends an
	 * authentication request to the specified provider. By default is unset.
	 *
	 * @param singleProviderURI Provider URI (a.k.a. OP Identifier).
	 *
	 * @throws URISyntaxException If the specified URI is invalid.
	 */
	public void setSingleProviderURI(String singleProviderURI)
		throws URISyntaxException {

		this.singleProviderURI = (singleProviderURI != null ?
				new URI(singleProviderURI) : null);
	}

	/**
	 * Get pattern for allowed claimed IDs.
	 *
	 * @return Regular expression for allowed claimed IDs, or {@code null} if
	 * anything is allowed.
	 */
	public String getAllowedClaimedIDPattern() {

		if (this.allowedClaimedIDPattern == null)
			return null;

		return this.allowedClaimedIDPattern.pattern();
	}

	/**
	 * Set pattern for allowed claimed IDs. Positive authentication assertions
	 * from OpenID providers will be accepted only if the claimed ID matches the
	 * pattern. Note, that if anything else except claimed ID is used as the
	 * user login name (see {@link #setLoginNameAttributeType}), the pattern is
	 * required. By default the pattern is not set, allowing any claimed ID.
	 *
	 * @param allowedClaimedIDPattern Regular expression for allowed claimed
	 * IDs, or {@code null} if anything is allowed.
	 */
	public void setAllowedClaimedIDPattern(String allowedClaimedIDPattern) {

		this.allowedClaimedIDPattern = (allowedClaimedIDPattern != null ?
				Pattern.compile(allowedClaimedIDPattern) : null);
	}

	/**
	 * Get OpenID Attribute Exchange extension attribute type of the attribute
	 * used as the login name with the realm.
	 *
	 * @return The attribute type id, or {@code null} for OpenID claimed
	 * identifier.
	 */
	public String getLoginNameAttributeType() {

		return this.loginNameAttributeType;
	}

	/**
	 * Set OpenID Attribute Exchange extension attribute type of the attribute
	 * used as the login name with the realm. If unset, OpenID claimed
	 * identifier is used.
	 *
	 * @param loginNameAttributeType The attribute type id.
	 */
	public void setLoginNameAttributeType(String loginNameAttributeType) {

		this.loginNameAttributeType = loginNameAttributeType;
		if (AX_ATT_NAMES.containsKey(this.loginNameAttributeType))
			this.loginNameAttributeName =
				AX_ATT_NAMES.get(this.loginNameAttributeType);
	}

	/**
	 * Get HTTP connect timeout used for direct communication with OpenID
	 * parties.
	 *
	 * @return Timeout in milliseconds.
	 */
	public int getHttpConnectTimeout() {

		return this.httpConnectTimeout;
	}

	/**
	 * Set HTTP connect timeout used for direct communication with OpenID
	 * parties. The default is {@link XRDSFactory#DEFAULT_HTTP_CONNECT_TO}.
	 *
	 * @param httpConnectTimeout Timeout in milliseconds.
	 *
	 * @see URLConnection#setConnectTimeout(int)
	 */
	public void setHttpConnectTimeout(int httpConnectTimeout) {

		this.httpConnectTimeout = httpConnectTimeout;
		this.xrdsFactory.setHttpConnectTimeout(httpConnectTimeout);
	}

	/**
	 * Get HTTP read timeout used for direct communication with OpenID parties.
	 *
	 * @return Timeout in milliseconds.
	 */
	public int getHttpReadTimeout() {

		return this.httpReadTimeout;
	}

	/**
	 * Set HTTP read timeout used for direct communication with OpenID parties.
	 * The default is {@link XRDSFactory#DEFAULT_HTTP_READ_TO}.
	 *
	 * @param httpReadTimeout Timeout in milliseconds.
	 *
	 * @see URLConnection#setReadTimeout(int)
	 */
	public void setHttpReadTimeout(int httpReadTimeout) {

		this.httpReadTimeout = httpReadTimeout;
		this.xrdsFactory.setHttpReadTimeout(httpReadTimeout);
	}

	/**
	 * Tell if the authenticator should send the browser HTML form to
	 * automatically submit authentication request to the OpenID provider.
	 *
	 * @return {@code true} to make browser submit authentication request on its
	 * own.
	 */
	public boolean isBrowserRedirect() {

		return this.browserRedirect;
	}

	/**
	 * Set flag tell if the authenticator should send the browser HTML form to
	 * automatically submit authentication request to the OpenID provider. If
	 * {@code false}, the authenticator submits the authentication request
	 * itself and expects a redirect response, which is then sent back to the
	 * browser. This is more efficient, but does not work with all OpenID
	 * providers. The default is {@code true}.
	 *
	 * @param browserRedirect {@code true} to make browser submit authentication
	 * request on its own.
	 */
	public void setBrowserRedirect(boolean browserRedirect) {

		this.browserRedirect = browserRedirect;
	}

	/**
	 * Tell if the authenticator is in development mode.
	 *
	 * @return {@code true} if in development mode.
	 */
	public boolean isDevelopmentMode() {

		return this.developmentMode;
	}

	/**
	 * Set flag telling if the authenticator should work in development mode. In
	 * development mode the authenticator does not send the user to the actual
	 * OpenID provider to login. Instead, it shows a built-in login page where
	 * the user can specify the user name and return back to the application
	 * authenticated in as the specified user.
	 *
	 * @param developmentMode {@code true} to turn on development mode.
	 */
	public void setDevelopmentMode(boolean developmentMode) {

		this.developmentMode = developmentMode;
	}


	/* (non-Javadoc)
	 * @see org.apache.catalina.authenticator.FormAuthenticator#getInfo()
	 */
	@Override
	public String getInfo() {

		return INFO;
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.authenticator.AuthenticatorBase#startInternal()
	 */
	@Override
	protected synchronized void startInternal()
		throws LifecycleException {

		if (!(this.context.getRealm() instanceof OpenIDRealm))
			throw new LifecycleException(
					"No OpenIDRealm in the authenticator's context.");

		super.startInternal();
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.authenticator.AuthenticatorBase#invoke(org.apache.catalina.connector.Request, org.apache.catalina.connector.Response)
	 */
	@Override
	public void invoke(Request request, Response response)
		throws IOException, ServletException {

		// check if show mock login page action
		final String requestURI = request.getDecodedRequestURI();
		final String contextPath = request.getContextPath();
		if (requestURI.startsWith(contextPath)
				&& requestURI.endsWith(MOCK_LOGIN_ACTION_URI)) {
			if (this.log.isDebugEnabled())
				this.log.debug("sending mock login page");
			this.sendMockLoginPage(request, response);
			return;
		}

		// proceed normally
		super.invoke(request, response);
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.authenticator.FormAuthenticator#authenticate(org.apache.catalina.connector.Request, javax.servlet.http.HttpServletResponse, org.apache.catalina.deploy.LoginConfig)
	 */
	@Override
	public boolean authenticate(Request request, HttpServletResponse response,
			LoginConfig config)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("authenticating request");

		// check if already authenticated
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			if (debug)
				this.log.debug("already authenticated " + principal.getName());
			return true;
		}

		// TODO: single sign-on logic

		// check if original request after successful authentication
		if (this.matchRequest(request)) {
			if (debug)
				this.log.debug("original request resubmission after" +
						" successful authentication");
			this.processOriginalRequestResubmission(request, response);
			if (debug)
				this.log.debug("restored original request, proceeding");
			return true;
		}

		// check if authenticator action
		final String requestURI = request.getDecodedRequestURI();
		final String contextPath = request.getContextPath();
		if (requestURI.startsWith(contextPath)
				&& requestURI.endsWith(Constants.FORM_ACTION)) {

			// send ack
			request.getResponse().sendAcknowledgement();

			// set request encoding before reading parameters
			if (this.characterEncoding != null)
				request.setCharacterEncoding(this.characterEncoding);

			// detect and process action
			String openId = this.getRequestParam(request, OPENID_ID_PARAM);
			if (openId != null)
				this.processRequestAuthentication(request, response, config,
						openId);
			else if (request.getParameter("openid.ns") != null)
				this.processLogin(request, response, config);
			else
				this.processFormLogin(request, response, config);

			// done
			return false;
		}

		// reauthenticate if cache is disabled
		if (!this.cache) {
			String loginName;
			String password;
			final Session session = request.getSessionInternal(false);
			if ((session != null)
					&& ((loginName = (String) session.getNote(
							Constants.SESS_USERNAME_NOTE)) != null)
					&& ((password = (String) session.getNote(
							Constants.SESS_PASSWORD_NOTE)) != null)) {
				if (debug)
					this.log.debug("cache is disabled, reauthenticating " +
							loginName);
				final OpenIDRealm realm = (OpenIDRealm) this.context.getRealm();
				if (session.getNote(OPENID_AUTH_NOTE) != null) {
					principal = realm.authenticateOpenID(loginName);
				} else {
					principal = realm.authenticate(loginName, password);
				}
				if (principal != null) {
					if (debug)
						this.log.debug("successful reauthentication");
					this.register(request, response, principal,
							this.getAuthMethod(), loginName, password);
					return true;
				}
				if (debug)
					this.log.debug("reauthentication failed");
				session.removeNote(Constants.SESS_USERNAME_NOTE);
				session.removeNote(Constants.SESS_PASSWORD_NOTE);
				session.removeNote(OPENID_AUTH_NOTE);
			}
		}

		// unauthenticated request
		if (debug)
			this.log.debug("unauthenticated request, saving it and forwarding" +
					" to the login page");

		// save the original request in the session
		this.saveRequest(request, request.getSessionInternal(true));

		// require authentication
		if (this.singleProviderURI != null) {
			this.processRequestAuthentication(request, response, config,
					this.singleProviderURI.toString());
		} else {
			this.forwardToLoginPage(request, response, config);
		}

		// done
		return false;
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.authenticator.AuthenticatorBase#logout(org.apache.catalina.connector.Request)
	 */
	@Override
	public void logout(Request request)
		throws ServletException {

		Session session = request.getSessionInternal(false);
		if (session != null) {
			session.removeNote(Constants.FORM_PRINCIPAL_NOTE);
			session.removeNote(Constants.SESS_USERNAME_NOTE);
			session.removeNote(Constants.SESS_PASSWORD_NOTE);
			session.removeNote(OPENID_AUTH_NOTE);
		}

		super.logout(request);
	}


	/**
	 * Process request authentication authenticator action.
	 *
	 * @param request The request.
	 * @param response The HTTP response.
	 * @param config Web-application login configuration.
	 * @param openId Open ID parameter value (a.k.a. user-supplied identifier).
	 *
	 * @throws IOException If an I/O error happens sending data in the response
	 * or unexpected I/O error communicating with the OP provider.
	 */
	protected void processRequestAuthentication(Request request,
			HttpServletResponse response, LoginConfig config, String openId)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// check if development mode
		if (this.developmentMode) {
			if (debug)
				this.log.debug("development mode, redirecting to the mock" +
						" login page");
			response.sendRedirect(response.encodeRedirectURL(
					request.getContextPath() + MOCK_LOGIN_ACTION_URI));
			return;
		}

		// get user-supplied id

		// normalize user-supplied id
		String usId = openId;
		Matcher m = XRI_PATTERN.matcher(usId);
		final boolean usIdIsXRI = m.matches();
		if (usIdIsXRI) {
			usId = m.group(1);
		} else {
			try {
				URI usIdURI = new URI(usId);
				String scheme = usIdURI.getScheme();
				if (scheme == null)
					usId = "http://" + usId;
				else if (!scheme.equalsIgnoreCase("http")
						&& !scheme.equalsIgnoreCase("https")) {
					if (debug)
						this.log.debug("invalid user-supplied id scheme: " +
								scheme);
					this.forwardToErrorPage(request, response, config);
					return;
				}
			} catch (URISyntaxException e) {
				if (debug)
					this.log.debug("invalid user-supplied id", e);
				this.forwardToErrorPage(request, response, config);
				return;
			}
		}

		// get the OP end-point URL
		URL opURL = null;
		String claimedId = "http://specs.openid.net/auth/2.0/identifier_select";
		String localId = claimedId;
		if (usIdIsXRI) {

			// get the XRD containing the required SEP
			String serviceType;
			XRD xrd;
			try {
				serviceType = XRD_SERVER_SERVICE_TYPE;
				if (debug)
					this.log.debug("user-supplied id is an XRI," +
							" trying to resolve it to OP end-point URL");
				xrd = this.xrdsFactory.resolveXRI(usId, serviceType);
				if (xrd == null) {
					if (debug)
						this.log.debug("no server service, trying signon");
					serviceType = XRD_SIGNON_SERVICE_TYPE;
					xrd = this.xrdsFactory.resolveXRI(usId, serviceType);
				}
				if (xrd == null) {
					if (debug)
						this.log.debug(
								"neither server nor sigon service found");
					this.forwardToErrorPage(request, response, config);
					return;
				}
			} catch (MalformedURLException e) {
				if (debug)
					this.log.debug("invalid user-supplied id XRI", e);
				this.forwardToErrorPage(request, response, config);
				return;
			} catch (SAXException e) {
				throw new IOException(
						"Error parsing response from the XRI resolver: " +
								e.getMessage(), e);
			}

			// check if canonical ID was verified successfully
			if (xrd.getCidVerificationStatus() !=
					XRD.CIDVerificationStatus.VERIFIED) {
				if (debug)
					this.log.debug(
							"canonical ID was not verified successfully");
				this.forwardToErrorPage(request, response, config);
				return;
			}

			// get the SEP
			SEP sep = xrd.selectSEP(URI.create(serviceType), null, null, 0);
			if (sep == null) {
				if (debug)
					this.log.debug("no required SEP in the XRD");
				this.forwardToErrorPage(request, response, config);
				return;
			}

			// get the OP end-point URL
			URI uri = sep.getURI();
			if (uri == null) {
				if (debug)
					this.log.debug("no URI in the SEP");
				this.forwardToErrorPage(request, response, config);
				return;
			}
			opURL = uri.toURL();

			// get the claimed ID
			uri = xrd.getCanonicalID();
			if (uri == null) {
				if (debug)
					this.log.debug("no canonical ID in the XRD");
				this.forwardToErrorPage(request, response, config);
				return;
			}
			claimedId = uri.toString();

			// get the local ID
			uri = sep.getLocalID();
			if (uri == null)
				uri = xrd.getLocalID();
			localId = (uri != null ? uri.toString() : claimedId);

		} else { // user-supplied id is a URL

			try {

				// perform discovery
				XRDSHTTPDiscoveryResult res =
					this.xrdsFactory.discover(new URL(usId));
				XRD xrd = res.getFinalXRD();

				// get the SEP from the XRD if found
				SEP sep = null;
				if (xrd != null) {

					// try server SEP
					sep = xrd.selectSEP(URI.create(XRD_SERVER_SERVICE_TYPE),
							null, null, 0);

					// try signon SEP if no server SEP
					if (sep == null) {

						// try to find signon SEP
						sep = xrd.selectSEP(URI.create(XRD_SIGNON_SERVICE_TYPE),
								null, null, 0);
						if (sep == null) {
							if (debug)
								this.log.debug(
										"no server or signon SEP in the XRDS");
							this.forwardToErrorPage(request, response, config);
							return;
						}

						// get claimed id
						claimedId = this.normalizeHTTPURI(
								URI.create(res.getLastRequestURL().toString()))
								.toString();

						// get local id
						URI uri = sep.getLocalID();
						if (uri == null)
							uri = xrd.getLocalID();
						localId = (uri != null ? uri.toString() : claimedId);
					}
				}

				// get OP end-point URL from the SEP if found
				if (sep != null) {

					URI uri = sep.getURI();
					if (uri == null) {
						if (debug)
							this.log.debug("no URI in the SEP");
						this.forwardToErrorPage(request, response, config);
						return;
					}
					opURL = uri.toURL();

				} else {

					// attempt HTML discovery if no XRD or SEP
					if (HTML_CONTENT_TYPE.equals(
							res.getLastResponseContentType())) {

						// parse the HTML
						OpenIDHTMLParseResult htmlRes =
							this.parseOpenIDHTML(res.getLastResponseContent());
						if (htmlRes == null) {
							this.forwardToErrorPage(request, response,
									config);
							return;
						}

						// get the OP end-point URL
						opURL = htmlRes.opURL;
						if (opURL == null) {
							if (debug)
								this.log.debug("no openid2.provider link in" +
										" the HTML");
							this.forwardToErrorPage(request, response,
									config);
							return;
						}

						// get claimed id
						claimedId = this.normalizeHTTPURI(
								URI.create(res.getLastRequestURL().toString()))
								.toString();

						// get local id
						localId = (htmlRes.localId != null ?
								htmlRes.localId : claimedId);

					} else {
						if (debug)
							this.log.debug("could not resolve user-supplied" +
									" id to XRDS or HTML");
						this.forwardToErrorPage(request, response, config);
						return;
					}
				}

			} catch (HTTPErrorException e) {
				if (debug)
					this.log.debug("HTTP error doing discovery", e);
				this.forwardToErrorPage(request, response, config);
				return;

			} catch (SAXException e) {
				throw new IOException(
						"Error parsing XRDS response from the user-supplied" +
						" identifier URL: " + e.getMessage(), e);
			}
		}

		// discovery finished
		if (debug)
			this.log.debug("got OP end-point URL: [" + opURL +
					"], claimed ID: [" + claimedId + "], local ID: [" +
					localId + "]");

		// build authentication request parameters
		Map<String, String> params = new HashMap<String, String>();
		params.put("openid.ns", OPENID_NS);
		params.put("openid.mode", "checkid_setup");
		params.put("openid.claimed_id", claimedId);
		//params.put("openid.identity", localId); // TODO: local id is relative?
		params.put("openid.identity", claimedId);
		final String baseURL = this.getBaseURL(request);
		final String returnToURL = baseURL + Constants.FORM_ACTION;
		params.put("openid.realm", baseURL + "/");
		params.put("openid.return_to", returnToURL);
		if (this.loginNameAttributeType != null) {
			params.put("openid.ns.ax", XRD_AX_SERVICE_TYPE);
			params.put("openid.ax.mode", "fetch_request");
			params.put("openid.ax.type." + this.loginNameAttributeName,
					this.loginNameAttributeType);
			params.put("openid.ax.required", this.loginNameAttributeName);
		}

		// send authentication request to the OP
		if (this.browserRedirect) {

			// build authentication parameters HTML
			StringBuffer paramsHTML = new StringBuffer(1024);
			for (Map.Entry<String, String> entry : params.entrySet()) {
				paramsHTML.append("<input type=\"hidden\" name=\"")
				.append(entry.getKey()).append("\" value=\"")
				.append(this.escapeAttr(entry.getValue())).append("\"/>");
			}

			// send HTML
			Map<String, String> tmplParams = new HashMap<String, String>();
			tmplParams.put("opURL", this.escapeAttr(opURL.toString()));
			tmplParams.put("inputs", paramsHTML.toString());
			this.sendHTML("request-auth-tmpl.html", tmplParams, response);

		} else {

			// send authentication request to the OP and get redirect URL
			String redirUrl =
				this.httpPost(opURL, params, null, this.redirectContentHandler);
			if (redirUrl == null) {
				if (debug)
					this.log.debug("no redirect location in the response");
				this.forwardToErrorPage(request, response, config);
				return;
			}
			if (debug)
				this.log.debug("got redirect URL: " + redirUrl);

			// redirect to the OP for authentication
			response.sendRedirect(redirUrl);
		}
	}

	/**
	 * Process login authenticator action.
	 *
	 * @param request The request.
	 * @param response The HTTP response.
	 * @param config Web-application login configuration.
	 *
	 * @throws IOException If an I/O error happens sending data in the response.
	 */
	protected void processLogin(Request request, HttpServletResponse response,
			LoginConfig config)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// log the request
		if (debug) {
			StringBuffer msg = new StringBuffer(256);
			msg.append("callback from the OP to ")
			.append(request.getRequestURL());
			for (Map.Entry<String, String[]> entry :
				request.getParameterMap().entrySet()) {
				String name = entry.getKey();
				String[] vals = entry.getValue();
				if (vals.length > 1) {
					for (int i = 0; i < vals.length; i++)
						msg.append('\n').append(name).append(" [#").append(i)
						.append("]: ").append(vals[i]);
				} if (vals.length == 1) {
					msg.append('\n').append(name).append(": ").append(vals[0]);
				} else {
					msg.append('\n').append(name).append(':');
				}
			}
			this.log.debug(msg.toString());
		}

		// make sure it's an OpenID response
		if (!OPENID_NS.equals(request.getParameter("openid.ns"))) {
			if (debug)
				this.log.debug("invalid openid.ns parameter: " +
						request.getParameter("openid.ns"));
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		// check if "cancel"
		final String openIdMode = request.getParameter("openid.mode");
		if ("cancel".equals(openIdMode)) {
			if (debug)
				this.log.debug("user canceled login");
			this.forwardToErrorPage(request, response, config);
			return;
		}

		// verify it's "id_res" response
		if (!"id_res".equals(openIdMode)) {
			if (debug)
				this.log.debug("invalid or absent openid.mode parameter: " +
						openIdMode);
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		// verify the "return_to" field in the response
		final String returnToURL =
			this.getBaseURL(request) + Constants.FORM_ACTION;
		if (!returnToURL.equals(request.getParameter("openid.return_to"))) {
			if (debug)
				this.log.debug("return_to URL in the response [" +
						request.getParameter("openid.return_to") +
						"] does not match configured action URL [" +
						returnToURL + "], current request URL is [" +
						request.getRequestURL() + "]");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		// get the OP end-point URL
		String opURLStr = request.getParameter("openid.op_endpoint");
		if (opURLStr == null) {
			if (debug)
				this.log.debug("no openid.op_endpoint in the request");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		URL opURL;
		URI opURI;
		try {
			opURL = new URL(opURLStr);
			opURI = opURL.toURI();
		} catch (MalformedURLException e) {
			if (debug)
				this.log.debug("invalid openid.op_endpoint in the request", e);
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		} catch (URISyntaxException e) {
			if (debug)
				this.log.debug("invalid openid.op_endpoint in the request", e);
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		// get and verify the claimed identifier
		final String claimedId = request.getParameter("openid.claimed_id");
		if (claimedId == null) {
			if (debug)
				this.log.debug("no openid.claimed_id in the request");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		if (debug)
			this.log.debug("discovering claimed id [" + claimedId + "]");
		XRD claimedIdXRD = null;
		Matcher m = XRI_PATTERN.matcher(claimedId);
		if (m.matches()) {
			if (debug)
				this.log.debug("claimed id is an XRI, resolving it");

			// get the signon XRD
			try {
				claimedIdXRD = this.xrdsFactory.resolveXRI(m.group(1),
						XRD_SIGNON_SERVICE_TYPE);
				if (claimedIdXRD == null) {
					if (debug)
						this.log.debug("claimed id XRI did not resolve to an" +
								" XRD with signon SEP");
					response.sendError(HttpServletResponse.SC_BAD_REQUEST);
					return;
				}
			} catch (MalformedURLException e) {
				if (debug)
					this.log.debug("invalid openid.claimed_id in the request",
							e);
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			} catch (SAXException e) {
				throw new IOException(
						"Error parsing response from the XRI resolver: " +
								e.getMessage(), e);
			}

		} else { // claimed ID is not an XRI

			// check if claimed ID is a URL
			URL claimedIdURL;
			try {
				claimedIdURL = new URL(claimedId);
			} catch (MalformedURLException e) {
				if (debug)
					this.log.debug("openid.claimed_id is neither XRI nor URL",
							e);
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			}

			// attempt to discover XRD using the claimed ID as a URL
			try {
				XRDSHTTPDiscoveryResult res =
					this.xrdsFactory.discover(claimedIdURL);
				claimedIdXRD = res.getFinalXRD();

				// check if HTML discovery is needed
				if (claimedIdXRD == null) {
					if (HTML_CONTENT_TYPE.equals(
							res.getLastResponseContentType())) {

						// parse the HTML
						OpenIDHTMLParseResult htmlRes =
							this.parseOpenIDHTML(res.getLastResponseContent());
						if ((htmlRes == null) || (htmlRes.opURL == null)) {
							if (debug)
								this.log.debug(
										"could not get OP end-point URL from" +
										" the HTML behind the claimed id");
							response.sendError(
									HttpServletResponse.SC_BAD_REQUEST);
							return;
						}

						// validate the OP end-point URL
						if (!htmlRes.opURL.equals(opURL)) {
							if (debug)
								this.log.debug("openid.op_endpoint [" +
										opURLStr +
										"] does not match openid2.provider [" +
										htmlRes.opURL +
										"] in the claimed ID's HTML");
							response.sendError(
									HttpServletResponse.SC_BAD_REQUEST);
							return;
						}

						// validated
						if (debug)
							this.log.debug("validated claimed ID using HTML");

					} else {
						if (debug)
							this.log.debug("could not resolve claimed id to" +
									" XRDS or HTML");
						response.sendError(HttpServletResponse.SC_BAD_REQUEST);
						return;
					}
				}

			} catch (SAXException e) {
				throw new IOException(
						"Error parsing XRDS response from the claimed ID" +
						" URL: " + e.getMessage(), e);
			}
		}

		// validate claimed ID XRD
		if (claimedIdXRD != null) {

			// get all the signon SEPs
			Collection<SEP> seps =
				claimedIdXRD.findSEPs(URI.create(XRD_SIGNON_SERVICE_TYPE));
			if (seps.size() == 0) {
				if (debug)
					this.log.debug("no required SEP in the XRD");
				response.sendError(
						HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				return;
			}

			// check if OP end-point URI is among signon SEP URIs
			boolean found = false;
			for (SEP sep : seps) {
				if (sep.hasURI(opURI)) {
					found = true;
					break;
				}
			}
			if (!found) {
				if (debug)
					this.log.debug("openid.op_endpoint [" + opURLStr +
						"] is not among signon SEPs in the claimed ID's XRD");
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			}

			// validated
			if (debug)
				this.log.debug("validated claimed ID using XRD");
		}

		// validate claimed ID against configured allowed patterns
		if ((this.loginNameAttributeType != null)
				&& (this.allowedClaimedIDPattern == null)) {
			if (debug)
				this.log.debug("login name attribute is set but allowed" +
						" claimed IDs pattern is not");
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			return;
		}
		if (this.allowedClaimedIDPattern != null) {
			if (!this.allowedClaimedIDPattern.matcher(claimedId).matches()) {
				if (debug)
					this.log.debug("claimed ID does not match allowed claimed" +
							" IDs pattern");
				this.forwardToErrorPage(request, response, config);
				return;
			}
		}

		// verify signature
		if (debug)
			this.log.debug("validating the positive assertion response");
		Map<String, String> params = new HashMap<String, String>();
		params.put("openid.mode", "check_authentication");
		for (Enumeration<String> en = request.getParameterNames();
				en.hasMoreElements();) {
			final String paramName = en.nextElement();
			if (paramName.equals("openid.mode"))
				continue;
			params.put(paramName, request.getParameter(paramName));
		}
		Map<String, String> sigCheckResp = httpPost(opURL, params,
				TEXT_PLAIN_CONTENT_TYPE, this.oidRespContentHandler);
		if (!OPENID_NS.equals(sigCheckResp.get("ns"))
				|| !"true".equals(sigCheckResp.get("is_valid"))) {
			if (debug)
				this.log.debug("could not validate the positive assertion" +
						" response");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		if (debug)
			this.log.debug("asserted positive authentication of claimed id " +
					claimedId);

		// get login name
		String loginName = null;
		if (this.loginNameAttributeType != null) {
			for (Enumeration<String> en = request.getParameterNames();
					en.hasMoreElements();) {
				final String paramName = en.nextElement();
				if (!paramName.startsWith("openid.ns.")
						|| paramName.length() == "openid.ns.".length())
					continue;
				if (!XRD_AX_SERVICE_TYPE.equals(
						request.getParameter(paramName)))
					continue;
				final String alias =
					paramName.substring(paramName.lastIndexOf('.') + 1);
				if (!"fetch_response".equals(
						request.getParameter("openid." + alias + ".mode")))
					continue;
				if (!this.loginNameAttributeType.equals(
						request.getParameter("openid." + alias + ".type." +
								this.loginNameAttributeName)))
					continue;
				if (loginName != null) {
					if (debug)
						this.log.debug("more than one AX fetch response with " +
								this.loginNameAttributeName);
					response.sendError(HttpServletResponse.SC_BAD_REQUEST);
					return;
				}
				loginName =
					request.getParameter("openid." + alias + ".value." +
							this.loginNameAttributeName);
			}
			if (loginName == null) {
				if (debug)
					this.log.debug("no login name attribute in the" +
							" request");
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			}
		} else { // use claimed id
			loginName = claimedId;
		}

		// validate the user in the realm
		if (debug)
			this.log.debug("validating login name " + loginName +
					" in the realm");
		Principal principal =
			((OpenIDRealm) this.context.getRealm()).authenticateOpenID(
					loginName);

		// process authenticated user
		this.processAuthenticatedUser(request, response, config, principal,
				loginName, loginName, true);
	}

	/**
	 * Process form login authenticator action.
	 *
	 * @param request The request.
	 * @param response The HTTP response.
	 * @param config Web-application login configuration.
	 *
	 * @throws IOException If an I/O error happens sending data in the response.
	 */
	protected void processFormLogin(Request request,
			HttpServletResponse response, LoginConfig config)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// get user credentials from the form
		final String loginName = request.getParameter(Constants.FORM_USERNAME);
		final String password = request.getParameter(Constants.FORM_PASSWORD);

		// validate the user in the realm
		if (debug)
			this.log.debug("form authenticating login name " + loginName);
		Principal principal =
			this.context.getRealm().authenticate(loginName, password);

		// process authenticated user
		this.processAuthenticatedUser(request, response, config, principal,
				loginName, password, false);
	}

	/**
	 * Process authenticated user and redirect to the original request.
	 *
	 * @param request The request.
	 * @param response The HTTP response.
	 * @param config Web-application login configuration.
	 * @param principal Authenticated principal, or {@code null} if
	 * authentication was unsuccessful, in which case the method forwards to the
	 * configured error page.
	 * @param loginName User login name.
	 * @param password User password.
	 * @param openID {@code true} if OpenID authentication.
	 *
	 * @throws IOException If an I/O error happens sending data in the response.
	 */
	protected void processAuthenticatedUser(Request request,
			HttpServletResponse response, LoginConfig config,
			Principal principal, String loginName, String password,
			boolean openID)
		throws IOException {

		final boolean debug = this.log.isDebugEnabled();

		// check if user authenticated
		if (principal == null) {
			if (debug)
				this.log.debug("failed to authenticate the user in the" +
						" realm, forwarding to the error page");
			this.forwardToErrorPage(request, response, config);
			return;
		}
		if (debug)
			this.log.debug("successfully authenticated user " +
					principal.getName());

		// save the principal data for the original request restoration
		Session session = request.getSessionInternal(true);
		session.setNote(Constants.FORM_PRINCIPAL_NOTE, principal);
		session.setNote(Constants.SESS_USERNAME_NOTE, loginName);
		session.setNote(Constants.SESS_PASSWORD_NOTE, password);
		if (openID)
			session.setNote(OPENID_AUTH_NOTE, Boolean.TRUE);

		// get saved request URL from the session
		String savedRequestURL = this.savedRequestURL(session);
		if (savedRequestURL == null) {
			savedRequestURL = request.getContextPath() +
					(this.landingPage != null ? this.landingPage : "");
			if (debug)
				this.log.debug("no saved requested in the session, making" +
						" it GET " + savedRequestURL);
			SavedRequest saved = new SavedRequest();
			saved.setMethod("GET");
			saved.setRequestURI(savedRequestURL);
			saved.setDecodedRequestURI(savedRequestURL);
			session.setNote(Constants.FORM_REQUEST_NOTE, saved);
		}

		// redirect to the original request URL
		if (debug)
			this.log.debug("redirecting to the original request URL at " +
					savedRequestURL);
		response.sendRedirect(response.encodeRedirectURL(savedRequestURL));
	}

	/**
	 * Process re-submission of the original request after successful
	 * authentication.
	 *
	 * @param request The request.
	 * @param response The HTTP response.
	 *
	 * @throws IOException If an I/O error happens sending data in the response.
	 */
	protected void processOriginalRequestResubmission(Request request,
			HttpServletResponse response)
		throws IOException {

		// get the session
		Session session = request.getSessionInternal(true);

		// get authenticated principal from the session and register it
		Principal principal =
			(Principal) session.getNote(Constants.FORM_PRINCIPAL_NOTE);
		this.register(request, response, principal, this.getAuthMethod(),
				(String) session.getNote(Constants.SESS_USERNAME_NOTE),
				(String) session.getNote(Constants.SESS_PASSWORD_NOTE));

		// remove unused attributes from the session
		session.removeNote(Constants.FORM_PRINCIPAL_NOTE);
		if (this.cache) {
			session.removeNote(Constants.SESS_USERNAME_NOTE);
			session.removeNote(Constants.SESS_PASSWORD_NOTE);
			session.removeNote(OPENID_AUTH_NOTE);
		}

		// restore the original request context
		if (this.log.isDebugEnabled())
			this.log.debug("restoring original request context");
		this.restoreRequest(request, session);
	}

	/**
	 * Send mock login page.
	 *
	 * @param request The request.
	 * @param response The HTTP response.
	 *
	 * @throws IOException If an I/O error happens sending data in the response.
	 */
	protected void sendMockLoginPage(Request request,
			HttpServletResponse response)
		throws IOException {

		// process the template
		Map<String, String> tmplParams = new HashMap<String, String>();
		tmplParams.put("contextPath", request.getContextPath());
		tmplParams.put("loginNameParam",
				(this.loginNameAttributeType != null ?
						"openid.ext1.value.loginName" : "openid.claimed_id"));
		if (this.loginNameAttributeType != null)
			tmplParams.put("loginNameAttType", this.loginNameAttributeType);

		// send the page
		this.sendHTML("mock-login-tmpl.html", tmplParams, response);
	}

	/**
	 * Send HTML response.
	 *
	 * @param tmplRsrc HTML template resource name.
	 * @param tmplParams Parameters for the template.
	 * @param response The HTTP response.
	 *
	 * @throws IOException If an I/O error happens sending the response.
	 */
	private void sendHTML(String tmplRsrc, Map<String, String> tmplParams,
			HttpServletResponse response)
		throws IOException {

		// load the mock login page template
		char[] buf = new char[4096];
		StringBuffer tmplBuf = new StringBuffer(buf.length);
		InputStreamReader in = new InputStreamReader(
				this.getClass().getResourceAsStream(tmplRsrc), "UTF-8");
		try {
			int n;
			while ((n = in.read(buf)) >= 0)
				tmplBuf.append(buf, 0, n);
		} finally {
			in.close();
		}

		// process the template
		Matcher m = TMPL_PARAM_PATTERN.matcher(tmplBuf.toString());
		tmplBuf.setLength(0);
		while (m.find()) {
			String val = tmplParams.get(m.group(1));
			m.appendReplacement(tmplBuf,
					(val != null ? val.replaceAll("[\\\\$]", "\\\\$0") : ""));
		}
		m.appendTail(tmplBuf);
		String html = tmplBuf.toString();

		// send the HTML
		byte[] contentBytes = html.getBytes("UTF-8");
		response.setContentType("text/html; charset=UTF-8");
		response.setContentLength(contentBytes.length);
		response.getOutputStream().write(contentBytes);
	}

	/**
	 * Get request parameter.
	 *
	 * @param request The request.
	 * @param paramName Parameter name.
	 *
	 * @return Trimmed parameter value, or {@code null} if parameter is absent
	 * or blank.
	 */
	private String getRequestParam(Request request, String paramName) {

		String val = request.getParameter(paramName);
		if (val == null)
			return null;

		val = val.trim();
		if (val.length() == 0)
			return null;

		return val;
	}

	/**
	 * Get content from a URL using HTTP POST.
	 *
	 * @param <T> Return type of the content handler.
	 *
	 * @param url The URL.
	 * @param data Data to send.
	 * @param accept Accepted response content type, or {@code null} if any.
	 * @param contentHandler Response content handler to use.
	 *
	 * @return The response object.
	 *
	 * @throws IOException If an I/O error happens.
	 */
	private <T> T httpPost(URL url, Map<String, String> data,
			String accept, ResponseContentHandler<T> contentHandler)
		throws IOException {

		StringBuffer body = new StringBuffer(512);
		for (Map.Entry<String, String> entry : data.entrySet()) {
			String paramName = entry.getKey();
			String paramValue = entry.getValue();
			if (body.length() > 0)
				body.append('&');
			body.append(URLEncoder.encode(paramName, "UTF-8"))
			.append('=').append(URLEncoder.encode(paramValue, "UTF-8"));
		}

		if (this.log.isDebugEnabled())
			this.log.debug("posting data to " + url + ": " + body);

		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setConnectTimeout(this.httpConnectTimeout);
		con.setReadTimeout(this.httpReadTimeout);
		con.setInstanceFollowRedirects(false);
		con.setDoOutput(true);

		if (accept != null)
			con.addRequestProperty("Accept", accept);

		ByteArrayOutputStream respBuf = new ByteArrayOutputStream(4096);
		byte[] buf = new byte[512];
		OutputStream out = con.getOutputStream();
		try {
			out.write(body.toString().getBytes("UTF-8"));
			out.flush();
			InputStream in = con.getInputStream();
			try {
				int n;
				while ((n = in.read(buf)) >= 0)
					respBuf.write(buf, 0, n);
			} finally {
				in.close();
			}
		} finally {
			out.close();
		}

		T resp = contentHandler.getContent(con, respBuf);

		if (this.log.isDebugEnabled()) {
			this.log.debug("response headers: " +
					this.getResponseHeadersString(con));
			this.log.debug("response content: " +
					contentHandler.getContentString(con, respBuf));
		}

		return resp;
	}

	/**
	 * Get HTTP response headers as a string for debug logging.
	 *
	 * @param con The HTTP connection.
	 *
	 * @return The headers.
	 */
	private String getResponseHeadersString(HttpURLConnection con) {

		StringBuffer res = new StringBuffer(512);
		int i = 0;
		String val;
		do {
			String name = con.getHeaderFieldKey(i);
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
	 * Get web-application base URL (either from the {@code hostBaseURI}
	 * authenticator property or auto-detected from the request).
	 *
	 * @param request The request.
	 *
	 * @return Base URL. 
	 */
	private String getBaseURL(Request request) {

		if (this.hostBaseURI != null)
			return this.hostBaseURI + request.getContextPath();

		final StringBuffer baseURLBuf = new StringBuffer(64);
		baseURLBuf.append("https://").append(request.getServerName());
		final int port = request.getServerPort();
		if (port != 443)
			baseURLBuf.append(':').append(port);
		baseURLBuf.append(request.getContextPath());

		return baseURLBuf.toString();
	}

	/**
	 * Normalize HTTP(S) URI to make it usable as a claimed ID.
	 *
	 * @param uri The URI.
	 *
	 * @return Normalized URI.
	 *
	 * @throws IllegalArgumentException If the specified URI is not a valid
	 * absolute HTTP(S) URI.
	 */
	private URI normalizeHTTPURI(URI uri) {

		if (uri.isOpaque() || !uri.isAbsolute())
			throw new IllegalArgumentException(
					"The specified URI is not a valid HTTP(S) URI:" +
					" opaque or relative.");

		String scheme = uri.getScheme();
		if (scheme == null)
			scheme = "http";
		else
			scheme = scheme.toLowerCase();
		if (!scheme.equals("http") && !scheme.equals("https"))
			throw new IllegalArgumentException(
					"The specified URI is not a valid HTTP(S) URI:" +
					" scheme is not http(s).");

		String host = uri.getHost();
		if (host == null)
			throw new IllegalArgumentException(
					"The specified URI is not a valid HTTP(S) URI:" +
					" no host.");
		host = host.toLowerCase();

		int port = uri.getPort();
		if (port != -1) {
			if ((scheme.equals("http") && (port == 80))
					|| (scheme.equals("https") && (port == 443)))
				port = -1;
		}

		String path = uri.getPath();
		if ((path == null) || (path.length() == 0))
			path = "/";

		String query = uri.getQuery();
		if ((query != null) && (query.length() == 0))
			query = null;

		try {
			return (new URI(scheme, uri.getUserInfo(), host, port, path, query,
					null)).normalize();
		} catch (URISyntaxException e) {
			// cannot be
			throw new Error(e);
		}
	}

	/**
	 * Extract OpenID links from HTML.
	 *
	 * @param html The HTML.
	 *
	 * @return The result, or {@code null} if errors.
	 */
	private OpenIDHTMLParseResult parseOpenIDHTML(String html) {

		final boolean debug = this.log.isDebugEnabled();

		OpenIDHTMLParseResult res = new OpenIDHTMLParseResult();

		Matcher m = HTML_FIND_OP2_LINKS_PATTERN.matcher(
				HTML_EXTRACT_HEAD_PATTERN.matcher(
						HTML_REMOVE_COMMENTS_PATTERN.matcher(html)
						.replaceAll(""))
				.replaceFirst("$1"));
		while (m.find()) {

			String rel = m.group(1);
			String href;
			if (rel != null) {
				href = m.group(2);
			} else {
				rel = m.group(4);
				href = m.group(3);
			}

			if (rel.equals("openid2.provider")) {

				if (res.opURL != null) {
					if (debug)
						this.log.debug("more than one openid2.provider link" +
								" in the HTML");
					return null;
				}
				try {
					res.opURL = new URL(href);
				} catch (MalformedURLException e) {
					if (debug)
						this.log.debug("invalid openid2.provider link in" +
								" the HTML", e);
					return null;
				}

			} else if (rel.equals("openid2.local_id")) {

				if (res.localId != null) {
					if (debug)
						this.log.debug("more than one openid2.local_id link" +
								" in the HTML");
					return null;
				}
				res.localId = href;
			}
		}

		return res;
	}

	/**
	 * Escape string to make it HTML attribute value.
	 *
	 * @param val Value.
	 *
	 * @return Safe value.
	 */
	private String escapeAttr(String val) {

		return val.replaceAll("&", "&amp;").replaceAll("\"", "&quot;");
	}
}
