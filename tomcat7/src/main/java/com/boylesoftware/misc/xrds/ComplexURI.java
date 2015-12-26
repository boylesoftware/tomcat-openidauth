package com.boylesoftware.misc.xrds;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;


/**
 * URI that can have a priority and an "append" attribute.
 *
 * @author Lev Himmelfarb
 */
class ComplexURI {

	/**
	 * Random number generator.
	 */
	private static final Random RAND = new Random();


	/**
	 * Append mode.
	 */
	enum Append {

		/**
		 * Nothing to append.
		 */
		NONE,

		/**
		 * Append path and/or query.
		 */
		LOCAL,

		/**
		 * Append authority.
		 */
		AUTHORITY,

		/**
		 * Append path.
		 */
		PATH,

		/**
		 * Append query.
		 */
		QUERY,

		/**
		 * Append entire QXRI.
		 */
		QXRI;


		/**
		 * Get enum value from {@code append} attribute value.
		 *
		 * @param attVal The attribute value as it appears in the XRD. Can be
		 * {@code null}.
		 *
		 * @return Corresponding enumeration value, or {@code null} if the
		 * {@code attVal} is {@code null}.
		 */
		public static Append fromAttribute(String attVal) {

			if (attVal == null)
				return null;

			return Append.valueOf(attVal.toUpperCase());
		}
	}


	/**
	 * The URI.
	 */
	private final URI uri;

	/**
	 * The priority.
	 */
	private final int priority;

	/**
	 * The append mode.
	 */
	private final Append append;


	/**
	 * Create new complex URI object.
	 *
	 * @param uri The URI.
	 * @param priority The priority. If {@code null}, {@link Integer#MAX_VALUE}
	 * is used.
	 * @param append The append mode. If {@code null}, {@link Append#NONE}
	 * is used.
	 */
	ComplexURI(URI uri, Integer priority, Append append) {

		this.uri = uri;
		this.priority =
			(priority != null ? priority.intValue() : Integer.MAX_VALUE);
		this.append = (append != null ? append : Append.NONE);
	}


	/**
	 * Get unmodified by the {@code append} attribute URI.
	 *
	 * @return The URI.
	 */
	public URI getURI() {

		return this.uri;
	}

	/**
	 * Get the priority.
	 *
	 * @return The priority, which may be {@link Integer#MAX_VALUE} if priority
	 * was not specified.
	 */
	public int getPriority() {

		return this.priority;
	}

	/**
	 * Get the append mode.
	 *
	 * @return The append mode. Never {@code null}, but can be
	 * {@link Append#NONE}.
	 */
	public Append getAppend() {

		return this.append;
	}


	/**
	 * Randomly select a highest priority URI from the specified collection.
	 *
	 * @param curis Collection, from which to select.
	 *
	 * @return Selected URI, or {@code null} if the collection is empty.
	 *
	 * @throws NullPointerException If the specified collection is {@code null}.
	 */
	public static ComplexURI select(Collection<ComplexURI> curis) {

		if (curis.isEmpty())
			return null;

		List<ComplexURI> selected = new ArrayList<ComplexURI>(
				curis.size() > 10 ? curis.size() : 10);
		int highestPri = Integer.MAX_VALUE;
		for (ComplexURI curi : curis) {
			final int pri = curi.getPriority();
			if (pri > highestPri)
				continue;
			if (pri < highestPri) {
				selected.clear();
				highestPri = pri;
			}
			selected.add(curi);
		}

		return selected.get(RAND.nextInt(selected.size()));
	}
}
