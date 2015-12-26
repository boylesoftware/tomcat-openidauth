package org.bsworks.misc.xrds;


/**
 * MediaType SEL.
 *
 * @author Lev Himmelfarb
 */
class MediaTypeSEL
	extends SEL<String> {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 1L;


	/**
	 * Create new SEL.
	 *
	 * @param value SEL value.
	 * @param select Select attribute.
	 * @param match Match attribute, or {@code null}.
	 */
	MediaTypeSEL(final String value, final boolean select, final Match match) {
		super(SELType.MEDIA_TYPE, String.class, value, select, match);
	}


	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	protected boolean matchValue(final String queryValue) {

		return queryValue.equalsIgnoreCase(this.value);
	}
}
