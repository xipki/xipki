/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.common.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XmlUtil {

    static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    private static Document document;

    private static DocumentBuilder builder;

    static {
        try {
            builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        } catch (ParserConfigurationException ex) {
            System.err.println("could not initialize the XMLDocumentBuilder. Message: "
                    + ex.getMessage());
            System.err.println("could not initialize the XMLDocumentBuilder" + ex.getMessage());
        }
        if (builder != null) {
            document = builder.newDocument();
        }
    }

    private XmlUtil() {
    }

    public static Element createElement(
            final String namespace,
            final String localPart,
            final String value) {
        if (document == null) {
            throw new RuntimeException("XMLDocumentBuilder must not be initialized");
        }
        ParamUtil.requireNonBlank("localPart", localPart);
        Element element = document.createElementNS(namespace, "ns:" + localPart);
        if (StringUtil.isNotBlank(value)) {
            element.appendChild(document.createTextNode(value));
        }
        return element;
    }

    public static Element getDocumentElment(
            final byte[] xmlFragement)
    throws IOException, SAXException {
        ParamUtil.requireNonNull("xmlFragement", xmlFragement);
        Document doc = builder.parse(new ByteArrayInputStream(xmlFragement));
        return doc.getDocumentElement();
    }

    public static Calendar getCalendar(
            final Date dateAndTime) {
        if (null == dateAndTime) {
            return null;
        }
        Calendar cal = (Calendar) Calendar.getInstance(UTC).clone();
        cal.setTime(dateAndTime);
        return cal;
    }

    public static XMLGregorianCalendar currentXmlDate() {
        return getXmlDate(new Date());
    }

    public static XMLGregorianCalendar getXmlDate(
            final Calendar calendar) {
        ParamUtil.requireNonNull("calendar", calendar);
        GregorianCalendar cal;
        if (calendar instanceof GregorianCalendar) {
            cal = (GregorianCalendar) calendar;
        } else {
            cal = new GregorianCalendar();
            cal.setTimeZone(UTC);
            cal.setTime(calendar.getTime());
        }

        try {
            XMLGregorianCalendar ret = DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);
            ret.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
            return ret;
        } catch (DatatypeConfigurationException ex) {
            return null;
        }
    }

    public static XMLGregorianCalendar getXmlDate(
            final Date dateAndTime) {
        ParamUtil.requireNonNull("dateAndTime", dateAndTime);
        GregorianCalendar cal = new GregorianCalendar();
        cal.setTimeZone(UTC);
        cal.setTime(dateAndTime);

        try {
            XMLGregorianCalendar ret = DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);
            ret.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
            return ret;
        } catch (DatatypeConfigurationException ex) {
            return null;
        }
    }

    public static String getValueOfFirstElementChild(
            final Element element,
            final String namespace,
            final String localname) {
        Node node = getFirstElementChild(element, namespace, localname);
        return (node == null)
                ? null
                : getNodeValue(node);
    }

    public static String getNodeValue(
            final Node node) {
        ParamUtil.requireNonNull("node", node);
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            Node cn = node.getFirstChild();
            if (cn != null) {
                do {
                    if (cn.getNodeType() == Node.TEXT_NODE) {
                        return cn.getNodeValue();
                    }
                    cn = cn.getNextSibling();
                } while (cn != null);
            }
        }

        return node.getNodeValue();
    }

    public static Element getFirstElementChild(
            final Element element,
            final String namespace,
            final String localname) {
        ParamUtil.requireNonNull("element", element);
        ParamUtil.requireNonBlank("localname", localname);
        Node node = element.getFirstChild();
        if (node == null) {
            return null;
        }

        do {
            if (match(node, namespace, localname)) {
                return (Element) node;
            }
            node = node.getNextSibling();
        } while (node != null);
        return null;
    }

    /**
     *
     * @param element context element.
     * @param namespace namespace of the expected element. Set it to {@code null} if namespace
     *     will not be evaluated.
     * @param localname localname of the expected element.
     * @return List of the expected children element. If no match children could be found, empty
     *     list will be returned.
     */
    public static List<Element> getElementChilden(
            final Element element,
            final String namespace,
            final String localname) {
        ParamUtil.requireNonNull("element", element);
        ParamUtil.requireNonBlank("localname", localname);
        List<Element> rv = new LinkedList<Element>();
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (match(child, namespace, localname)) {
                rv.add((Element) child);
            }
        }

        return rv;
    }

    public static List<Element> getAllElementsWithAttrId(
            final Element element,
            final String namespace) {
        ParamUtil.requireNonNull("element", element);
        List<Element> list = new LinkedList<Element>();
        if (elementHasId(element, namespace)) {
            list.add(element);
        }

        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (!(child instanceof Element)) {
                continue;
            }

            addAllElementsWithAttrId(list, (Element) child, namespace);
        }

        return list;
    }

    private static void addAllElementsWithAttrId(
            final List<Element> list,
            final Element element,
            final String namespace) {
        if (elementHasId(element, namespace)) {
            list.add(element);
        }

        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (!(child instanceof Element)) {
                continue;
            }

            Element childElement = (Element) child;
            if (elementHasId(childElement, namespace)) {
                list.add(childElement);
            }

            addAllElementsWithAttrId(list, childElement, namespace);
        }
    }

    private static boolean elementHasId(
            final Element element,
            final String namespace) {
        return element.hasAttributeNS(namespace, "Id");
    }

    private static boolean match(
            final Node node,
            final String namespace,
            final String localname) {
        if (node instanceof Element) {
            Element element = (Element) node;
            String ln = element.getLocalName();
            if (ln == null) {
                ln = element.getTagName();
            }
            if (ln.equals(localname)) {
                if (namespace == null || namespace.equals(element.getNamespaceURI())) {
                    return true;
                }
            }
        }

        return false;
    }

    public static String getValueOfFirstMatch(
            final Element contextNode,
            final String relativeXpath,
            final Map<String, String> nsPrefixUriMap) {
        Node node = getFirstMatch(contextNode, relativeXpath, nsPrefixUriMap);
        return (node == null)
                ? null
                : getNodeValue(node);
    }

    public static Node getFirstMatch(
            final Element contextNode,
            final String relativeXPath,
            final Map<String, String> nsPrefixUriMap) {
        List<Node> nodes = getMatch(contextNode, relativeXPath, nsPrefixUriMap, true);
        return CollectionUtil.isEmpty(nodes)
                ? null
                : nodes.get(0);
    }

    public static List<Node> getMatch(
            final Element contextNode,
            final String relativeXPath,
            final Map<String, String> nsPrefixUriMap) {
        return getMatch(contextNode, relativeXPath, nsPrefixUriMap, false);
    }

    private static List<Node> getMatch(
            final Element contextNode,
            final String relativeXpath,
            final Map<String, String> nsPrefixUriMap,
            final boolean onlyFirstMatch) {
        try {
            SimpleXpath simpleXpath = new SimpleXpath(relativeXpath, nsPrefixUriMap);
            if (onlyFirstMatch) {
                Node node = simpleXpath.selectFirstMatch(contextNode);
                if (node == null) {
                    return Collections.emptyList();
                } else {
                    return Arrays.asList(node);
                }
            } else {
                return simpleXpath.select(contextNode);
            }
        } catch (XPathExpressionException ex) {
            System.err.println("invalid xpath {}" + relativeXpath);
            return Collections.emptyList();
        }
    }

    public static List<Element> getElementMatch(
            final Element contextNode,
            final String relativeXpath,
            final Map<String, String> nsPrefixUriMap) {
        List<Node> nodes = getMatch(contextNode, relativeXpath, nsPrefixUriMap, false);
        List<Element> elements = new ArrayList<Element>(nodes.size());
        for (Node node : nodes) {
            if (node instanceof Element) {
                elements.add((Element) node);
            }
        }
        return elements;
    }

    public static String getMessage(
            final JAXBException ex) {
        ParamUtil.requireNonNull("ex", ex);
        String ret = ex.getMessage();
        if (ret == null && ex.getLinkedException() != null) {
            ret = ex.getLinkedException().getMessage();
        }
        return ret;
    }

    public static JAXBException convert(
            final JAXBException ex) {
        ParamUtil.requireNonNull("ex", ex);
        return new JAXBException(getMessage(ex), ex.getLinkedException());
    }

}
