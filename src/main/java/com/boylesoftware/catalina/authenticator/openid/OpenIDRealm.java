package com.boylesoftware.catalina.authenticator.openid;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.apache.catalina.Realm;
import org.apache.catalina.realm.CombinedRealm;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;


/**
 * Special realm implementation used with the {@link OpenIDAuthenticator}.
 *
 * @author Lev Himmelfarb
 */
public class OpenIDRealm
	extends CombinedRealm {

	/**
	 * Descriptive information about the realm implementation.
	 */
	private static final String INFO =
		(OpenIDRealm.class).getName() + "/1.0";

	/**
	 * Realm name.
	 */
	private static final String NAME = "OpenIDRealm";


	/**
	 * Authentication method interface.
	 */
	private static interface AuthenticationMethod {

		/**
		 * Perform authentication.
		 *
		 * @param realm Realm for authentication.
		 *
		 * @return Authenticated user, or {@code null} if unsuccessful.
		 */
		Principal authenticate(Realm realm);
	}


	/**
	 * The log.
	 */
	private final Log log = LogFactory.getLog(this.getClass());


	/* (non-Javadoc)
	 * @see org.apache.catalina.realm.RealmBase#getInfo()
	 */
	@Override
	public String getInfo() {

		return INFO;
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.realm.CombinedRealm#getName()
	 */
	@Override
	protected String getName() {

		return NAME;
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.realm.CombinedRealm#authenticate(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public Principal authenticate(final String username,
			final String clientDigest, final String nonce, final String nc,
			final String cnonce, final String qop, final String realmName,
			final String md5a2) {

		return this.authenticate(new AuthenticationMethod() {
			@Override
			public Principal authenticate(Realm realm) {

				return realm.authenticate(username, clientDigest, nonce, nc,
						cnonce, qop, realmName, md5a2);
			}
		}, username);
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.realm.CombinedRealm#authenticate(java.lang.String, java.lang.String)
	 */
	@Override
	public Principal authenticate(final String username,
			final String credentials) {

		return this.authenticate(new AuthenticationMethod() {
			@Override
			public Principal authenticate(Realm realm) {

				return realm.authenticate(username, credentials);
			}
		}, username);
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.realm.CombinedRealm#authenticate(java.security.cert.X509Certificate[])
	 */
	@Override
	public Principal authenticate(final X509Certificate[] certs) {

		String username = null;
		if ((certs != null) && (certs.length > 0))
			username = certs[0].getSubjectDN().getName();

		return this.authenticate(new AuthenticationMethod() {
			@Override
			public Principal authenticate(Realm realm) {

				return realm.authenticate(certs);
			}
		}, username);
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.realm.CombinedRealm#authenticate(org.ietf.jgss.GSSContext, boolean)
	 */
	@Override
	public Principal authenticate(final GSSContext gssContext,
			final boolean storeCreds) {

		String username = null;
		try {
			username = gssContext.getSrcName().toString();
		} catch (GSSException e) {
			this.log.warn(sm.getString("realmBase.gssNameFail"), e);
			return null;
		}

		return this.authenticate(new AuthenticationMethod() {
			@Override
			public Principal authenticate(Realm realm) {

				return realm.authenticate(gssContext, storeCreds);
			}
		}, username);
	}

	/**
	 * Perform authentication against non-OpenID realms.
	 *
	 * @param method Authentication method.
	 * @param username User login name.
	 *
	 * @return Authenticated user, or {@code null} if unsuccessful.
	 */
	private Principal authenticate(AuthenticationMethod method,
			String username) {

		final boolean debug = this.log.isDebugEnabled();
		if (debug)
			this.log.debug("authenticating " + username);

		Iterator<Realm> i = this.realms.iterator();
		if (!i.hasNext()) {
			if (debug)
				this.log.debug("no realms, authentication unsuccessful");
			return null;
		}
		i.next();

		Principal authenticatedUser = null;
		while (i.hasNext()) {
			Realm realm = i.next();
			authenticatedUser = method.authenticate(realm);
			if (authenticatedUser == null) {
				if (debug)
					this.log.debug("failed to authenticate " + username +
							" in " + realm.getInfo());
			} else {
				if (debug)
					this.log.debug("authenticated " + username + " in " +
							realm.getInfo());
				break;
			}
		}

		return authenticatedUser;
	}


	/**
	 * Authenticate using the OpenID realm.
	 *
	 * @param username The user name (used as password as well).
	 *
	 * @return Authenticated principal, or {@code null} if authentication was
	 * unsuccessful.
	 */
	Principal authenticateOpenID(String username) {

		if (this.realms.size() == 0)
			return null;

		return this.realms.get(0).authenticate(username, username);
	}
}
