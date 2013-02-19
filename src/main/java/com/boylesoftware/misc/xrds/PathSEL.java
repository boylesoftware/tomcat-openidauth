package com.boylesoftware.misc.xrds;


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
	 * @param match Match atttibute, or {@code null}.
	 */
	PathSEL(String value, boolean select,
			com.boylesoftware.misc.xrds.SEL.Match match) {
		super(SELType.PATH, String.class, value, select, match);

		this.valueNormal = (this.value != null ?
				(this.value.charAt(0) != '/' ? "/" + this.value : this.value)
				.toLowerCase() : null);
	}


	/* (non-Javadoc)
	 * @see com.boylesoftware.misc.xrds.SEL#matchValue(java.lang.Object)
	 */
	@Override
	protected boolean matchValue(String queryValue) {

		if (!this.valueNormal.startsWith(queryValue.toLowerCase()))
			return false;

		final int queryValueLen = queryValue.length();
		if (this.valueNormal.length() == queryValueLen)
			return true;

		char nextChar = this.valueNormal.charAt(queryValueLen);
		for (char separatorChar : SEGMENT_SEPARATORS)
			if (nextChar == separatorChar)
				return true;

		return false;
	}
}
