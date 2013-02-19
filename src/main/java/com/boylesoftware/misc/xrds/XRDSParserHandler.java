package com.boylesoftware.misc.xrds;

import java.net.URI;
import java.net.URISyntaxException;

import javax.xml.bind.DatatypeConverter;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.AttributesImpl;
import org.xml.sax.helpers.DefaultHandler;


/**
 * Handler used by {@link XRDSFactory} to parse XRDS documents.
 *
 * @author Lev Himmelfarb
 */
class XRDSParserHandler
	extends DefaultHandler {

	/**
	 * Namespace for the generic XRDS schema.
	 */
	private static final String XRDS_NS = "xri://$xrds";

	/**
	 * Namespace for the XRD 2.0 schema.
	 */
	private static final String XRD20_NS = "xri://$xrd*($v*2.0)";


	/**
	 * Final XRD.
	 */
	private XRD finalXRD;

	/**
	 * Current XRD.
	 */
	private XRD xrd;

	/**
	 * Current SEP.
	 */
	private SEP sep;

	/**
	 * Current element attributes.
	 */
	private final AttributesImpl elAtts = new AttributesImpl();

	/**
	 * Current element content.
	 */
	private final StringBuffer elContent = new StringBuffer(256);


	/**
	 * Get final XRD from the parsed XRDS.
	 *
	 * @return The XRD, or {@code null} if no XRDs found.
	 */
	public XRD getXRD() {

		return this.finalXRD;
	}


	/* (non-Javadoc)
	 * @see org.xml.sax.helpers.DefaultHandler#startElement(java.lang.String, java.lang.String, java.lang.String, org.xml.sax.Attributes)
	 */
	@Override
	public void startElement(String uri, String localName, String qName,
			Attributes attributes)
		throws SAXException {

		final boolean xrdNS = XRD20_NS.equals(uri);
		if (xrdNS && localName.equals("Service")) {
			if (this.xrd == null)
				throw new SAXException(
						"Service element is not a child of an XRD element.");
			if (this.sep != null)
				throw new SAXException("Nested Service element.");
			String priority = attributes.getValue("priority");
			this.sep = new SEP(
					(priority != null ? Integer.valueOf(priority) : null));
		} else if (xrdNS && localName.equals("XRD")) {
			if (this.xrd != null)
				throw new SAXException("Nested XRD element.");
			this.xrd = new XRD(attributes.getValue("xml:id"),
					attributes.getValue("idref"));
		} else if (XRDS_NS.equals(uri) && localName.equals("XRDS")) {
			// nothing, ignore the XRDS (top or nested)
		} else {
			this.elAtts.setAttributes(attributes);
			this.elContent.setLength(0);
		}
	}

	/* (non-Javadoc)
	 * @see org.xml.sax.helpers.DefaultHandler#endElement(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public void endElement(String uri, String localName, String qName)
		throws SAXException {

		final boolean xrdNS = XRD20_NS.equals(uri);
		if (xrdNS && localName.equals("Service")) {
			this.xrd.addSEP(this.sep);
			this.sep = null;
		} else if (xrdNS && localName.equals("XRD")) {
			this.finalXRD = this.xrd;
			this.xrd = null;
		} else if (XRDS_NS.equals(uri) && localName.equals("XRDS")) {
			// nothing, ignore the XRDS (top or nested)
		} else {
			if (xrdNS) {
				try {
					if (this.sep != null)
						this.processSEPSubelement(localName);
					else if (this.xrd != null)
						this.processXRDSubelement(localName);
				} catch (URISyntaxException e) {
					throw new SAXException("Invalid URI attribute value.", e);
				}
			} else if (this.sep != null) {
				this.sep.addProperty(
						(uri != null ? "{" + uri + "}" + localName : localName),
						this.elContent.toString());
			}
		}
	}

	/**
	 * Process XRD sub-element.
	 *
	 * @param localName Sub-element local name.
	 *
	 * @throws URISyntaxException If a URI attribute has an invalid value.
	 */
	private void processXRDSubelement(String localName)
		throws URISyntaxException {

		if (localName.equals("Type")) {
			this.xrd.addType(new URI(this.elContent.toString()));

		} else if (localName.equals("Query")) {
			this.xrd.setQuery(this.elContent.toString());

		} else if (localName.equals("Status")) {
			this.xrd.setStatus(
					Integer.parseInt(this.elAtts.getValue("code")),
					XRD.CIDVerificationStatus.fromAttribute(
							this.elAtts.getValue("cid")),
					XRD.CIDVerificationStatus.fromAttribute(
							this.elAtts.getValue("ceid")),
					this.elContent.toString());

		} else if (localName.equals("ServerStatus")) {
			this.xrd.setServerStatus(
					Integer.parseInt(
							this.elAtts.getValue("code")),
					this.elContent.toString());

		} else if (localName.equals("Expires")) {
			this.xrd.setExpires(DatatypeConverter.parseDateTime(
					this.elContent.toString()).getTime());

		} else if (localName.equals("ProviderID")) {
			this.xrd.setProviderID(new URI(this.elContent.toString()));

		} else if (localName.equals("Redirect")) {
			String priority = this.elAtts.getValue("priority");
			this.xrd.addRedirect(
					new URI(this.elContent.toString()),
					(priority != null ? Integer.valueOf(priority) : null),
					ComplexURI.Append.fromAttribute(
							this.elAtts.getValue("append")));

		} else if (localName.equals("Ref")) {
			String priority = this.elAtts.getValue("priority");
			this.xrd.addRef(new URI(this.elContent.toString()),
					(priority != null ? Integer.valueOf(priority) : null));

		} else if (localName.equals("LocalID")) {
			String priority = this.elAtts.getValue("priority");
			this.xrd.addLocalID(new URI(this.elContent.toString()),
					(priority != null ? Integer.valueOf(priority) : null));

		} else if (localName.equals("EquivID")) {
			String priority = this.elAtts.getValue("priority");
			this.xrd.addEquivID(new URI(this.elContent.toString()),
					(priority != null ? Integer.valueOf(priority) : null));

		} else if (localName.equals("CanonicalID")) {
			this.xrd.setCanonicalID(new URI(this.elContent.toString()));

		} else if (localName.equals("CanonicalEquivID")) {
			this.xrd.setCanonicalEquivID(new URI(this.elContent.toString()));
		}
	}

	/**
	 * Process Service sub-element.
	 *
	 * @param localName Sub-element local name.
	 *
	 * @throws URISyntaxException If a URI attribute has an invalid value.
	 */
	private void processSEPSubelement(String localName)
		throws URISyntaxException {

		if (localName.equals("ProviderID")) {
			this.sep.setProviderID(new URI(this.elContent.toString()));

		} else if (localName.equals("Type")) {
			this.sep.addType(this.elContent.toString(),
					Boolean.parseBoolean(this.elAtts.getValue("select")),
					SEL.Match.fromAttribute(this.elAtts.getValue("match")));

		} else if (localName.equals("Path")) {
			this.sep.addPath(this.elContent.toString(),
					Boolean.parseBoolean(this.elAtts.getValue("select")),
					SEL.Match.fromAttribute(this.elAtts.getValue("match")));

		} else if (localName.equals("MediaType")) {
			this.sep.addMediaType(this.elContent.toString(),
					Boolean.parseBoolean(this.elAtts.getValue("select")),
					SEL.Match.fromAttribute(this.elAtts.getValue("match")));

		} else if (localName.equals("URI")) {
			String priority = this.elAtts.getValue("priority");
			this.sep.addURI(
					new URI(this.elContent.toString()),
					(priority != null ? Integer.valueOf(priority) : null),
					ComplexURI.Append.fromAttribute(
							this.elAtts.getValue("append")));

		} else if (localName.equals("Redirect")) {
			String priority = this.elAtts.getValue("priority");
			this.sep.addRedirect(
					new URI(this.elContent.toString()),
					(priority != null ? Integer.valueOf(priority) : null),
					ComplexURI.Append.fromAttribute(
							this.elAtts.getValue("append")));

		} else if (localName.equals("Ref")) {
			String priority = this.elAtts.getValue("priority");
			this.sep.addRef(new URI(this.elContent.toString()),
					(priority != null ? Integer.valueOf(priority) : null));

		} else if (localName.equals("LocalID")) {
			String priority = this.elAtts.getValue("priority");
			this.sep.addLocalID(new URI(this.elContent.toString()),
					(priority != null ? Integer.valueOf(priority) : null));
		}
	}

	/* (non-Javadoc)
	 * @see org.xml.sax.helpers.DefaultHandler#characters(char[], int, int)
	 */
	@Override
	public void characters(char[] ch, int start, int length) {

		this.elContent.append(ch, start, length);
	}


	/* (non-Javadoc)
	 * @see org.xml.sax.helpers.DefaultHandler#warning(org.xml.sax.SAXParseException)
	 */
	@Override
	public void warning(SAXParseException e)
		throws SAXException {

		throw e;
	}

	/* (non-Javadoc)
	 * @see org.xml.sax.helpers.DefaultHandler#error(org.xml.sax.SAXParseException)
	 */
	@Override
	public void error(SAXParseException e)
		throws SAXException {

		throw e;
	}
}
