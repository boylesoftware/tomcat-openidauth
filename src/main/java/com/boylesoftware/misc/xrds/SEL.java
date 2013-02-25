package com.boylesoftware.misc.xrds;

import java.io.Serializable;


/**
 * Abstract SEP selection element.
 *
 * @author Lev Himmelfarb
 *
 * @param <T> Type of object used to match against this type of SEL.
 */
abstract class SEL<T>
	implements Serializable {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 1L;


	/**
	 * Positive match result.
	 */
	public static final int POSITIVE_MATCH = 1;

	/**
	 * Default match result.
	 */
	public static final int DEFAULT_MATCH = 0;

	/**
	 * Negative match result.
	 */
	public static final int NEGATIVE_MATCH = -1;


	/**
	 * SEL type.
	 */
	enum SELType {

		/**
		 * Type.
		 */
		TYPE(XRD.NODEFAULT_T),

		/**
		 * Path
		 */
		PATH(XRD.NODEFAULT_P),

		/**
		 * Media type.
		 */
		MEDIA_TYPE(XRD.NODEFAULT_M);


		/**
		 * Corresponding {@code nodefault_x} flag.
		 */
		private final int noDefaultFlag;


		/**
		 * Create new value.
		 *
		 * @param noDefaultFlag Corresponding {@code nodefault_x} flag.
		 */
		private SELType(int noDefaultFlag) {

			this.noDefaultFlag = noDefaultFlag;
		}


		/**
		 * Get Corresponding {@code nodefault_x} flag.
		 *
		 * @return {@link XRD#NODEFAULT_T}, {@link XRD#NODEFAULT_P} or
		 * {@link XRD#NODEFAULT_M}.
		 */
		public int getNoDefaultFlag() {

			return this.noDefaultFlag;
		}
	}


	/**
	 * Match mode.
	 */
	enum Match {

		/**
		 * Automatically a positive match.
		 */
		ANY,

		/**
		 * Automatically a default match.
		 */
		DEFAULT,

		/**
		 * Anything except null is a match.
		 */
		NON_NULL,

		/**
		 * Only null is a match.
		 */
		NULL;


		/**
		 * Get enum value from {@code match} attribute value.
		 *
		 * @param attVal The attribute value as it appears in the XRD. Can be
		 * {@code null}.
		 *
		 * @return Corresponding enumeration value, or {@code null} if the
		 * {@code attVal} is {@code null}.
		 */
		public static Match fromAttribute(String attVal) {

			if (attVal == null)
				return null;

			return Match.valueOf(attVal.toUpperCase().replace('-', '_'));
		}
	}


	/**
	 * SEL type.
	 */
	private final SELType type;

	/**
	 * Query value class.
	 */
	private final Class<T> queryValueClass;

	/**
	 * SEL value.
	 */
	protected final String value;

	/**
	 * Select attribute.
	 */
	private final boolean select;

	/**
	 * Match attribute.
	 */
	private final Match match;


	/**
	 * Create new SEL.
	 *
	 * @param type SEL type.
	 * @param queryValueClass Query value class.
	 * @param value SEL value. Cannot be {@code null}, but can be empty, in
	 * which case the {@code match} attribute is automatically set to
	 * {@link Match#NULL}.
	 * @param select {@code true} if this SEL has {@code select} attribute and
	 * it is "true".
	 * @param match Match attribute, or {@code null}.
	 */
	SEL(SELType type, Class<T> queryValueClass, String value, boolean select,
			Match match) {

		this.type = type;
		this.queryValueClass = queryValueClass;
		this.value = (value.length() > 0 ? value : null);
		this.select = select;
		this.match =
			((this.value == null) && (match == null) ? Match.NULL : match);
	}


	/**
	 * Tell if this SEL has {@code select} attribute equal "true".
	 *
	 * @return {@code true} if {@code select} attribute is present and is
	 * "true".
	 */
	public boolean isSelect() {

		return this.select;
	}

	/**
	 * Tell if this SEL matches the specified query value.
	 *
	 * @param queryValue The query value. May be {@code null}.
	 * @param flags Combination of {@link XRD#NODEFAULT_T},
	 * {@link XRD#NODEFAULT_P} and {@link XRD#NODEFAULT_M} flags, or zero.
	 *
	 * @return {@link #POSITIVE_MATCH}, {@link #DEFAULT_MATCH} or
	 * {@link #NEGATIVE_MATCH}.
	 */
	public final int match(Object queryValue, int flags) {

		if (this.match != null) {
			switch (this.match) {
			case ANY:
				return POSITIVE_MATCH;
			case DEFAULT:
				if ((flags & this.type.getNoDefaultFlag()) != 0)
					return NEGATIVE_MATCH;
				return DEFAULT_MATCH;
			case NON_NULL:
				if (queryValue != null)
					return POSITIVE_MATCH;
				return NEGATIVE_MATCH;
			case NULL:
				if (queryValue == null)
					return POSITIVE_MATCH;
				return NEGATIVE_MATCH;
			}
		}

		if (queryValue == null)
			return NEGATIVE_MATCH;

		return (this.matchValue(this.queryValueClass.cast(queryValue)) ?
					POSITIVE_MATCH : NEGATIVE_MATCH);
	}

	/**
	 * Tell if the value of this SEL matches the specified query value. This
	 * method is called only if this SEL does not have a {@code match}
	 * attribute (which also means that {@link #value} is not {@code null}).
	 *
	 * @param queryValue The query value, never {@code null}.
	 *
	 * @return {@code true} if positive match.
	 */
	protected abstract boolean matchValue(T queryValue);
}
