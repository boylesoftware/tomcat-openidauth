package org.bsworks.misc.xrds;


/**
 * Path SEL.
 *
 * @author Lev Himmelfarb
 */
class PathSEL
	extends SEL<String> {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 1L;


	/**
	 * XRI segment/subsegment separator characters.
	 */
	private static final char[] SEGMENT_SEPARATORS = new char[] {
		'/', '?', '#', '*', '!'
	};


	/**
	 * Value used for matching (always starting with a slash).
	 */
	private final String valueNormal;


	/**
	 * Create new SEL.
	 *
	 * @param value SEL value.
	 * @param select Select attribute.
	 * @param match Match attribute, or {@code null}.
	 */
	PathSEL(final String value, final boolean select,
			final org.bsworks.misc.xrds.SEL.Match match) {
		super(SELType.PATH, String.class, value, select, match);

		this.valueNormal = (this.value != null ?
				(this.value.charAt(0) != '/' ? "/" + this.value : this.value)
				.toLowerCase() : null);
	}


	/* (non-Javadoc)
	 * See overridden method.
	 */
	@Override
	protected boolean matchValue(final String queryValue) {

		if (!this.valueNormal.startsWith(queryValue.toLowerCase()))
			return false;

		final int queryValueLen = queryValue.length();
		if (this.valueNormal.length() == queryValueLen)
			return true;

		final char nextChar = this.valueNormal.charAt(queryValueLen);
		for (final char separatorChar : SEGMENT_SEPARATORS)
			if (nextChar == separatorChar)
				return true;

		return false;
	}
}
