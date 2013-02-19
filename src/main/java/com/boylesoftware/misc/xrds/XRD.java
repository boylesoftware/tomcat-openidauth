package com.boylesoftware.misc.xrds;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;


/**
 * Represents an XRD (eXtensible Resource Descriptor).
 *
 * @author Lev Himmelfarb
 */
public class XRD
	implements Serializable {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 1L;


	/**
	 * Random number generator.
	 */
	private static final Random RAND = new Random();

	/**
	 * Index for "present" match state.
	 */
	private static final int PRESENT = 0;

	/**
	 * Index for "default" match state.
	 */
	private static final int DEFAULT = 1;

	/**
	 * Index for "positive" match state.
	 */
	private static final int POSITIVE = 2;

	/**
	 * SEP selection logic flag {@code nodefault_t}.
	 */
	public static final int NODEFAULT_T = 1;

	/**
	 * SEP selection logic flag {@code nodefault_p}.
	 */
	public static final int NODEFAULT_P = 2;

	/**
	 * SEP selection logic flag {@code nodefault_m}.
	 */
	public static final int NODEFAULT_M = 4;

	/**
	 * Successful resolution status code.
	 */
	public static final int SC_SUCCESS = 100;


	/**
	 * CanonicalID and CanonicalEquivID verification status.
	 */
	public enum CIDVerificationStatus {

		/**
		 * The element is not present.
		 */
		ABSENT,

		/**
		 * Verification is not performed.
		 */
		OFF,

		/**
		 * The element is verified.
		 */
		VERIFIED,

		/**
		 * Verification fails.
		 */
		FAILED;


		/**
		 * Get enum value from {@code cid} or {@code ceid} attribute value.
		 *
		 * @param attVal The attribute value as it appears in the XRD. Can be
		 * {@code null}.
		 *
		 * @return Corresponding enumeration value, or {@code null} if the
		 * {@code attVal} is {@code null}.
		 */
		public static CIDVerificationStatus fromAttribute(String attVal) {

			if (attVal == null)
				return null;

			return CIDVerificationStatus.valueOf(attVal.toUpperCase());
		}
	}


	/**
	 * Resolution status code.
	 */
	private int statusCode = -1;

	/**
	 * Resolution canonical ID verification status.
	 */
	private CIDVerificationStatus cidVerificationStatus =
		CIDVerificationStatus.OFF;

	/**
	 * Resolution status message.
	 */
	private String statusMessage;

	/**
	 * Canonical ID.
	 */
	private URI canonicalID;

	/**
	 * Local IDs.
	 */
	private final Collection<ComplexURI> localIDs = new ArrayList<ComplexURI>();

	/**
	 * SEPs.
	 */
	private final Collection<SEP> seps = new ArrayList<SEP>();


	/**
	 * Create new XRD object.
	 *
	 * @param id XRD XML id, or {@code null}.
	 * @param idRef Reference to an XRD element in the parent XRDS, or
	 * {@code null}.
	 */
	XRD(@SuppressWarnings("unused") String id,
			@SuppressWarnings("unused") String idRef) {

		// nothing
	}


	/**
	 * Add XRD type.
	 *
	 * @param type The type.
	 */
	void addType(@SuppressWarnings("unused") URI type) {

		// nothing
	}

	/**
	 * Set query.
	 *
	 * @param query The query.
	 */
	void setQuery(@SuppressWarnings("unused") String query) {

		// nothing
	}

	/**
	 * Set resolution status.
	 *
	 * @param code Status code.
	 * @param cidVerificationStatus CanonicalID verification status.
	 * @param ceidStatus CanonicalEquivID verification status.
	 * @param message Status message.
	 */
	void setStatus(int code,
			CIDVerificationStatus cidVerificationStatus,
			@SuppressWarnings("unused") CIDVerificationStatus ceidStatus,
			String message) {

		this.statusCode = code;
		this.cidVerificationStatus = cidVerificationStatus;
		this.statusMessage = message;
	}

	/**
	 * Set server status.
	 *
	 * @param code Status code.
	 * @param message Status message.
	 */
	void setServerStatus(@SuppressWarnings("unused") int code,
			@SuppressWarnings("unused") String message) {

		// nothing
	}

	/**
	 * Set expiration date.
	 *
	 * @param date Expiration date.
	 */
	void setExpires(@SuppressWarnings("unused") Date date) {

		// nothing
	}

	/**
	 * Set provider URI.
	 *
	 * @param providerID Provider URI.
	 */
	void setProviderID(@SuppressWarnings("unused") URI providerID) {

		// nothing
	}

	/**
	 * Add redirect.
	 *
	 * @param uri Redirect URI.
	 * @param priority Redirect priority, or {@code null}.
	 * @param append URI append mode, or {@code null}.
	 */
	void addRedirect(@SuppressWarnings("unused") URI uri,
			@SuppressWarnings("unused") Integer priority,
			@SuppressWarnings("unused") ComplexURI.Append append) {

		// nothing
	}

	/**
	 * Add reference.
	 *
	 * @param uri Reference URI.
	 * @param priority Reference priority, or {@code null}.
	 */
	void addRef(@SuppressWarnings("unused") URI uri,
			@SuppressWarnings("unused") Integer priority) {

		// nothing
	}

	/**
	 * Add local ID.
	 *
	 * @param localID The ID.
	 * @param priority Priority, or {@code null}.
	 */
	void addLocalID(URI localID, Integer priority) {

		this.localIDs.add(new ComplexURI(localID, priority, null));
	}

	/**
	 * Add equivalent ID.
	 *
	 * @param uri The ID.
	 * @param priority Priority, or {@code null}.
	 */
	void addEquivID(@SuppressWarnings("unused") URI uri,
			@SuppressWarnings("unused") Integer priority) {

		// nothing
	}

	/**
	 * Set canonical ID.
	 *
	 * @param canonicalID The ID.
	 */
	void setCanonicalID(URI canonicalID) {

		this.canonicalID = canonicalID;
	}

	/**
	 * Set canonical equivalent ID.
	 *
	 * @param uri The ID.
	 */
	void setCanonicalEquivID(@SuppressWarnings("unused") URI uri) {

		// nothing
	}

	/**
	 * Add SEP.
	 *
	 * @param sep The SEP.
	 */
	void addSEP(SEP sep) {

		this.seps.add(sep);
	}


	/**
	 * Get resolution status code.
	 *
	 * @return Status code, or {@code -1} if status was not set.
	 */
	public int getStatusCode() {

		return this.statusCode;
	}

	/**
	 * Get canonical ID verification status.
	 *
	 * @return Canonical ID verification status. If status was not set, returns
	 * {@link CIDVerificationStatus#OFF}.
	 */
	public CIDVerificationStatus getCidVerificationStatus() {

		return this.cidVerificationStatus;
	}

	/**
	 * Get resolution status message.
	 *
	 * @return Status message, or {@code null} if status was not set.
	 */
	public String getStatusMessage() {

		return this.statusMessage;
	}

	/**
	 * Get canonical ID.
	 *
	 * @return Canonical ID, or {@code null}.
	 */
	public URI getCanonicalID() {

		return this.canonicalID;
	}

	/**
	 * Select local ID.
	 *
	 * @return Randomly selected highest priority local ID, or {@code null} if
	 * no local IDs in the XRD.
	 */
	public URI getLocalID() {

		ComplexURI selectedLID = ComplexURI.select(this.localIDs);
		if (selectedLID == null)
			return null;

		return selectedLID.getURI();
	}

	/**
	 * Find all SEPs with the specified type.
	 *
	 * @param type The SEP type.
	 *
	 * @return Unmodifiable collection of matched SEPs regardless of the
	 * priorities. Never {@code null}, but can be empty.
	 */
	public Collection<SEP> findSEPs(URI type) {

		return Collections.unmodifiableCollection(
				this.selectSEPs(type, null, null, 0));
	}

	/**
	 * Select a SEP from this XRD.
	 *
	 * @param type Requried SEP type, or {@code null} if irrelevant.
	 * @param path Required SEP path, or {@code null} if irrelevant.
	 * @param mediaType Required SEP media type, or {@code null} if irrelevant.
	 * @param flags Combination of {@link #NODEFAULT_T}, {@link #NODEFAULT_P}
	 * and {@link #NODEFAULT_M} flags, or zero.
	 *
	 * @return The SEP, or {@code null} if none matched.
	 */
	public SEP selectSEP(URI type, String path, String mediaType, int flags) {

		// match SEPs
		final List<SEP> selectedSEPs =
			this.selectSEPs(type, path, mediaType, flags);

		// got selected SEPs?
		if (selectedSEPs.isEmpty())
			return null;

		// select highest priority SEPs
		final List<SEP> highestPriSEPs = new ArrayList<SEP>(
				selectedSEPs.size() > 10 ? selectedSEPs.size() : 10);
		int highestPri = Integer.MAX_VALUE;
		for (Iterator<SEP> it = selectedSEPs.iterator(); it.hasNext();) {
			SEP sep = it.next();
			int pri = sep.getPriority();
			if (pri > highestPri)
				continue;
			if (pri < highestPri) {
				highestPriSEPs.clear();
				highestPri = pri;
			}
			highestPriSEPs.add(sep);
		}

		// pick remaing SEP randomly
		return highestPriSEPs.get(RAND.nextInt(highestPriSEPs.size()));
	}

	/**
	 * Execute SEP matching logic.
	 *
	 * @param type Requried SEP type, or {@code null} if irrelevant.
	 * @param path Required SEP path, or {@code null} if irrelevant.
	 * @param mediaType Required SEP media type, or {@code null} if irrelevant.
	 * @param flags Combination of {@link #NODEFAULT_T}, {@link #NODEFAULT_P}
	 * and {@link #NODEFAULT_M} flags, or zero.
	 *
	 * @return List of matched SEPs. Never {@code null}, but may be empty.
	 */
	private List<SEP> selectSEPs(URI type, String path, String mediaType,
			int flags) {

		final List<SEP> selectedSEPs = new ArrayList<SEP>(
				this.seps.size() > 10 ? this.seps.size() : 10);

		// loop through all SEPs
		final SEP[] defaultSEPs = new SEP[this.seps.size()];
		final Object[] queryValues = new Object[3];
		queryValues[SEL.SELType.TYPE.ordinal()] = type;
		queryValues[SEL.SELType.PATH.ordinal()] = path;
		queryValues[SEL.SELType.MEDIA_TYPE.ordinal()] = mediaType;
		final boolean[][][] matches = new boolean[this.seps.size()][3][3];
		int i = -1;
		SEP: for (SEP sep : this.seps) {

			i++;

			for (SEL.SELType selType : SEL.SELType.values()) {
				for (SEL<?> sel : sep.getSELs(selType)) {
					matches[i][selType.ordinal()][PRESENT] = true;
					switch (sel.match(queryValues[selType.ordinal()], flags)) {
					case SEL.POSITIVE_MATCH:
						if (sel.isSelect()) {
							selectedSEPs.add(sep);
							continue SEP;
						}
						matches[i][selType.ordinal()][POSITIVE] = true;
						break;
					case SEL.DEFAULT_MATCH:
						if (!matches[i][selType.ordinal()][POSITIVE])
							matches[i][selType.ordinal()][DEFAULT] = true;
					}
				}
				if (!matches[i][selType.ordinal()][PRESENT]
						&& ((flags & selType.getNoDefaultFlag()) == 0))
					matches[i][selType.ordinal()][DEFAULT] = true;
			}

			boolean allTrue = true;
			for (SEL.SELType selType : SEL.SELType.values()) {
				if (!matches[i][selType.ordinal()][POSITIVE]) {
					allTrue = false;
					break;
				}
			}
			if (allTrue) {
				selectedSEPs.add(sep);
				continue;
			}

			if (!selectedSEPs.isEmpty())
				continue;

			allTrue = true;
			for (SEL.SELType selType : SEL.SELType.values()) {
				if (!matches[i][selType.ordinal()][POSITIVE]
						&& !matches[i][selType.ordinal()][DEFAULT]) {
					allTrue = false;
					break;
				}
			}
			if (allTrue)
				defaultSEPs[i] = sep;
		}

		// degrade to double SEL positives
		if (selectedSEPs.isEmpty()) {
			for (i = 0; i < defaultSEPs.length; i++) {
				SEP sep = defaultSEPs[i];
				if (sep == null)
					continue;
				if ((matches[i][SEL.SELType.TYPE.ordinal()][POSITIVE]
						&& matches[i][SEL.SELType.PATH.ordinal()][POSITIVE])
					|| (matches[i][SEL.SELType.MEDIA_TYPE.ordinal()][POSITIVE]
						&& matches[i][SEL.SELType.TYPE.ordinal()][POSITIVE])
					|| (matches[i][SEL.SELType.MEDIA_TYPE.ordinal()][POSITIVE]
						&& matches[i][SEL.SELType.PATH.ordinal()][POSITIVE])) {
					selectedSEPs.add(sep);
				}
			}
		}

		// degrade to single SEL positives
		if (selectedSEPs.isEmpty()) {
			for (i = 0; i < defaultSEPs.length; i++) {
				SEP sep = defaultSEPs[i];
				if (sep == null)
					continue;
				if (matches[i][SEL.SELType.MEDIA_TYPE.ordinal()][POSITIVE]
						|| matches[i][SEL.SELType.PATH.ordinal()][POSITIVE]
						|| matches[i][SEL.SELType.TYPE.ordinal()][POSITIVE]) {
					selectedSEPs.add(sep);
				}
			}
		}

		// degrade to defaults
		if (selectedSEPs.isEmpty()) {
			for (i = 0; i < defaultSEPs.length; i++) {
				SEP sep = defaultSEPs[i];
				if (sep != null) {
					selectedSEPs.add(sep);
				}
			}
		}

		// return what's found
		return selectedSEPs;
	}
}
