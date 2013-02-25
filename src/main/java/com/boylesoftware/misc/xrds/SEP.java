package com.boylesoftware.misc.xrds;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * Represents a SEP (Service Endpoint).
 *
 * @author Lev Himmelfarb
 */
public class SEP
	implements Serializable {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 1L;


	/**
	 * Priority.
	 */
	private final int priority;

	/**
	 * SEP type SELs.
	 */
	private final Collection<TypeSEL> types = new ArrayList<TypeSEL>();

	/**
	 * SEP path SELs.
	 */
	private final Collection<PathSEL> paths = new ArrayList<PathSEL>();

	/**
	 * SEP media type SELs.
	 */
	private final Collection<MediaTypeSEL> mediaTypes =
		new ArrayList<MediaTypeSEL>();

	/**
	 * SEP URIs.
	 */
	private final Collection<ComplexURI> uris = new ArrayList<ComplexURI>();

	/**
	 * All SEP URIs in a set.
	 */
	private final Set<URI> allURIs = new HashSet<URI>();

	/**
	 * Local IDs.
	 */
	private final Collection<ComplexURI> localIDs = new ArrayList<ComplexURI>();

	/**
	 * SEP properties.
	 */
	private final Map<String, String> properties =
		new HashMap<String, String>();


	/**
	 * Create new SEP object.
	 *
	 * @param priority Priority. If {@code null}, {@link Integer#MAX_VALUE} is
	 * used.
	 */
	SEP(Integer priority) {

		this.priority =
			(priority != null ? priority.intValue() : Integer.MAX_VALUE);
	}


	/**
	 * Set provider ID.
	 *
	 * @param providerID The ID.
	 */
	void setProviderID(@SuppressWarnings("unused") URI providerID) {

		// nothing
	}

	/**
	 * Add SEP type SEL.
	 *
	 * @param value Type. Cannot be {@code null}, but can be empty.
	 * @param select Select attribute, or {@code false} if absent.
	 * @param match Match attribute, or {@code null}.
	 *
	 * @throws URISyntaxException If the specified value is not empty and is not
	 * a valid URI.
	 */
	void addType(String value, boolean select, SEL.Match match)
		throws URISyntaxException {

		this.types.add(new TypeSEL(value, select, match));
	}

	/**
	 * Add SEP path SEL.
	 *
	 * @param value Path. Cannot be {@code null}, but can be empty.
	 * @param select Select attribute, or {@code false} if absent.
	 * @param match Match attribute, or {@code null}.
	 */
	void addPath(String value, boolean select, SEL.Match match) {

		this.paths.add(new PathSEL(value, select, match));
	}

	/**
	 * Add SEP media type SEL.
	 *
	 * @param value Media type. Cannot be {@code null}, but can be empty.
	 * @param select Select attribute, or {@code false} if absent.
	 * @param match Match attribute, or {@code null}.
	 */
	void addMediaType(String value, boolean select, SEL.Match match) {

		this.mediaTypes.add(new MediaTypeSEL(value, select, match));
	}

	/**
	 * Add SEP URI.
	 *
	 * @param uri The URI.
	 * @param priority Priority, or {@code null}.
	 * @param append Append mode, or {@code null}.
	 */
	void addURI(URI uri, Integer priority, ComplexURI.Append append) {

		this.uris.add(new ComplexURI(uri, priority, append));
		this.allURIs.add(uri);
	}

	/**
	 * Add redirect.
	 *
	 * @param uri Redirect URI.
	 * @param priority Priority, or {@code null}.
	 * @param append Append mode, or {@code null}.
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
	 * @param priority Priority, or {@code null}.
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
	 * Add SEP property.
	 *
	 * @param name Property name.
	 * @param value Property value.
	 */
	void addProperty(String name, String value) {

		this.properties.put(name, value);
	}


	/**
	 * Get SELs of the specified type.
	 *
	 * @param type SEL type.
	 *
	 * @return Collection of the SELs. Never {@code null}, but can be empty.
	 */
	Collection<? extends SEL<?>> getSELs(SEL.SELType type) {

		switch (type) {
		case TYPE:
			return this.types;
		case PATH:
			return this.paths;
		default: // MEDIA_TYPE
			return this.mediaTypes;
		}
	}

	/**
	 * Get priority.
	 *
	 * @return The priority. If unspecified, return {@link Integer#MAX_VALUE}.
	 */
	int getPriority() {

		return this.priority;
	}


	/**
	 * Select SEP URI. The method does not perform the URI append logic as it
	 * assumes an empty QXRI.
	 *
	 * @return Randomly selected highest priority URI, or {@code null} if the
	 * SEP does not have URIs.
	 */
	public URI getURI() {

		ComplexURI selectedURI = ComplexURI.select(this.uris);

		if (selectedURI == null)
			return null;

		// append logic?

		return selectedURI.getURI();
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
	 * Tell if the SEP contains the specified URI. No append logic is performed,
	 * but all URIs regardless of the priorities are checked.
	 *
	 * @param uri The URI to test.
	 *
	 * @return {@code true} if the SEP contains the URI.
	 */
	public boolean hasURI(URI uri) {

		return this.allURIs.contains(uri);
	}
}
