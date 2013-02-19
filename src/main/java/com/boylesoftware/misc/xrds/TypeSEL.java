package com.boylesoftware.misc.xrds;

import java.net.URI;
import java.net.URISyntaxException;


/**
 * Type SEL.
 *
 * @author Lev Himmelfarb
 */
class TypeSEL
	extends SEL<URI> {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 1L;


	/**
	 * Normalized type URI.
	 */
	private final URI valueNormal;


	/**
	 * Create new SEL.
	 *
	 * @param value SEL value.
	 * @param select Select attribute.
	 * @param match Match atttibute, or {@code null}.
	 *
	 * @throws URISyntaxException If the specified value is not empty and not a
	 * valid URI.
	 */
	TypeSEL(String value, boolean select, Match match)
		throws URISyntaxException {
		super(SELType.TYPE, URI.class, value, select, match);

		this.valueNormal =
			(this.value != null ? new URI(this.value).normalize() : null);
	}


	/* (non-Javadoc)
	 * @see com.boylesoftware.misc.xrds.SEL#matchValue(java.lang.Object)
	 */
	@Override
	protected boolean matchValue(URI queryValue) {

		URI queryValueNormal = queryValue.normalize();
		if (!this.valueNormal.isOpaque() && !queryValueNormal.isOpaque()) {
			String path = this.valueNormal.getPath();
			String queryPath = queryValueNormal.getPath();
			if (path.equals("/") && queryPath.equals("")) {
				queryValueNormal =
					URI.create(queryValueNormal.toString() + "/");
			} else if (path.equals("") && queryPath.equals("/")) {
				String queryValueNormalString = queryValueNormal.toString();
				queryValueNormal =
					URI.create(queryValueNormalString.substring(0,
							queryValueNormalString.length() - 1));
			}
		}

		return this.valueNormal.equals(queryValueNormal);
	}
}
