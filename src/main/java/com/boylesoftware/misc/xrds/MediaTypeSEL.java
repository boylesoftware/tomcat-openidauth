package com.boylesoftware.misc.xrds;


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
	 * @param match Match atttibute, or {@code null}.
	 */
	MediaTypeSEL(String value, boolean select, Match match) {
		super(SELType.MEDIA_TYPE, String.class, value, select, match);
	}


	/* (non-Javadoc)
	 * @see com.boylesoftware.misc.xrds.SEL#matchValue(java.lang.Object)
	 */
	@Override
	protected boolean matchValue(String queryValue) {

		return queryValue.equalsIgnoreCase(this.value);
	}
}
