package org.bsworks.misc.xrds;

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
	 * @param match Match attribute, or {@code null}.
	 *
	 * @throws URISyntaxException If the specified value is not empty and not a
	 * valid URI.
	 */
	TypeSEL(final String value, final boolean select, final Match match)
		throws URISyntaxException {
		super(SELType.TYPE, URI.class, value, select, match);

		this.valueNormal =
			(this.value != null ? new URI(this.value).normalize() : null);
	}


	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	protected boolean matchValue(final URI queryValue) {

		URI queryValueNormal = queryValue.normalize();
		if (!this.valueNormal.isOpaque() && !queryValueNormal.isOpaque()) {
			final String path = this.valueNormal.getPath();
			final String queryPath = queryValueNormal.getPath();
			if (path.equals("/") && queryPath.equals("")) {
				queryValueNormal =
					URI.create(queryValueNormal.toString() + "/");
			} else if (path.equals("") && queryPath.equals("/")) {
				final String queryValueNormalString =
					queryValueNormal.toString();
				queryValueNormal =
					URI.create(queryValueNormalString.substring(0,
							queryValueNormalString.length() - 1));
			}
		}

		return this.valueNormal.equals(queryValueNormal);
	}
}
