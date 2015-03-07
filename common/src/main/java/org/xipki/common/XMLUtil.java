/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.common;

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
 */

public class XMLUtil
{
    static final TimeZone UTC = TimeZone.getTimeZone("UTC");
    private static Document document;
    private static DocumentBuilder builder;

    static
    {
        try
        {
            builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        } catch (ParserConfigurationException e)
        {
            System.err.println("Could not initialize the XMLDocumentBuilder. Message: " + e.getMessage());
            System.err.println("Could not initialize the XMLDocumentBuilder" + e.getMessage());
        }
        if(builder != null)
        {
            document = builder.newDocument();
        }
    }

    public static Element createElement(String namespace, String localPart, String value)
    {
        if(document == null)
        {
            throw new RuntimeException("XMLDocumentBuilder could not be initialized");
        }

        Element element = document.createElementNS(namespace, "ns:" + localPart);
        element.appendChild(document.createTextNode(value));
        return element;
    }

    public static Element getDocumentElment(byte[] xmlFragement)
    throws IOException, SAXException
    {
        Document doc = builder.parse(new ByteArrayInputStream(xmlFragement));
        return doc.getDocumentElement();
    }

    public static Calendar getCalendar(Date dateAndTime)
    {
        if ( null == dateAndTime )
        {
            return null;
        }
        Calendar cal = (Calendar) Calendar.getInstance(UTC).clone();
        cal.setTime(dateAndTime);
        return cal;
    }

    public static XMLGregorianCalendar currentXMLDate()
    {
        return getXMLDate(new Date());
    }

    public static XMLGregorianCalendar getXMLDate(Calendar calendar)
    {
        GregorianCalendar c;
        if(calendar instanceof GregorianCalendar)
        {
            c = (GregorianCalendar) calendar;
        }
        else
        {
            c = new GregorianCalendar();
            c.setTimeZone(UTC);
            c.setTime(calendar.getTime());
        }

        try
        {
            XMLGregorianCalendar ret = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
            ret.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
            return ret;
        } catch (DatatypeConfigurationException e)
        {
            return null;
        }
    }

    public static XMLGregorianCalendar getXMLDate(Date dateAndTime)
    {
        GregorianCalendar c = new GregorianCalendar();
        c.setTimeZone(UTC);
        c.setTime(dateAndTime);

        try
        {
            XMLGregorianCalendar ret = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
            ret.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
            return ret;
        } catch (DatatypeConfigurationException e)
        {
            return null;
        }
    }

    public static String getValueOfFirstElementChild(Element element, String namespace, String localname)
    {
        Node node = getFirstElementChild(element, namespace, localname);
        return (node==null) ? null : getNodeValue(node);
    }

    public static String getNodeValue(Node node)
    {
        if(node.getNodeType() == Node.ELEMENT_NODE)
        {
            Node n = node.getFirstChild();
            if(n != null)
            {
                do
                {
                    if(n.getNodeType() == Node.TEXT_NODE)
                    {
                        return n.getNodeValue();
                    }
                }while((n = n.getNextSibling()) != null);
            }
        }

        return node.getNodeValue();
    }

    public static Element getFirstElementChild(Element element, String namespace, String localname)
    {
        Node node = element.getFirstChild();
        if(node != null)
        {
            do
            {
                if(match(node, namespace, localname))
                {
                    return (Element) node;
                }
            } while((node = node.getNextSibling()) != null);
        }
        return null;
    }

    /**
     *
     * @param element context element.
     * @param namespace namespace of the expected element. Set it to {@code null} if namespace will not be evaluated.
     * @param localname localname of the expected element.
     * @return List of the expected children element. If no match children could be found, empty list will be returned.
     */
    public static List<Element> getElementChilden(Element element, String namespace, String localname)
    {
        List<Element> rv = new LinkedList<Element>();

        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++)
        {
            Node child = children.item(i);
            if(match(child, namespace, localname))
            {
                rv.add((Element) child);
            }
        }

        return rv;
    }

    public static List<Element> getAllElementsWithAttrId(Element element, String namespace)
    {
        List<Element> list = new LinkedList<Element>();
        if(elementHasId(element, namespace))
        {
            list.add(element);
        }

        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++)
        {
            Node child = children.item(i);
            if(child instanceof Element == false)
            {
                continue;
            }

            addAllElementsWithAttrId(list, (Element) child, namespace);
        }

        return list;
    }

    private static void addAllElementsWithAttrId(List<Element> list, Element element, String namespace)
    {
        if(elementHasId(element, namespace))
        {
            list.add(element);
        }

        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++)
        {
            Node child = children.item(i);
            if(child instanceof Element == false)
            {
                continue;
            }

            Element childElement = (Element) child;
            if(elementHasId(childElement, namespace))
            {
                list.add(childElement);
            }

            addAllElementsWithAttrId(list, childElement, namespace);
        }
    }

    private static boolean elementHasId(Element element, String namespace)
    {
        return element.hasAttributeNS(namespace, "Id");
    }

    private static boolean match(Node node, String namespace, String localname)
    {
        if(node instanceof Element)
        {
            Element element = (Element) node;
            if(element.getLocalName().equals(localname))
            {
                if(namespace == null || namespace.equals(element.getNamespaceURI()))
                {
                    return true;
                }
            }
        }

        return false;
    }

    public static String getValueOfFirstMatch(
            Element contextNode,
            String relativeXpath,
            Map<String, String> nsPrefixURIMap)
    {
        Node node = getFirstMatch(contextNode, relativeXpath, nsPrefixURIMap);
        return (node == null) ? null : getNodeValue(node);
    }

    public static Node getFirstMatch(
            Element contextNode,
            String relativeXPath,
            Map<String, String> nsPrefixURIMap)
    {
        List<Node> nodes = getMatch(contextNode, relativeXPath, nsPrefixURIMap, true);
        return CollectionUtil.isEmpty(nodes) ? null : nodes.get(0);
    }

    public static List<Node> getMatch(
            Element contextNode,
            String relativeXPath,
            Map<String, String> nsPrefixURIMap)
    {
        return getMatch(contextNode, relativeXPath, nsPrefixURIMap, false);
    }

    private static List<Node> getMatch(
            Element contextNode,
            String relativeXPath,
            Map<String, String> nsPrefixURIMap,
            boolean onlyFirstMatch)
    {
        try
        {
            SimpleXPath sXPath = new SimpleXPath(relativeXPath, nsPrefixURIMap);
            if(onlyFirstMatch)
            {
                Node node = sXPath.selectFirstMatch(contextNode);
                if(node == null)
                {
                    return Collections.emptyList();
                }
                else
                {
                    return Arrays.asList(node);
                }
            }
            else
            {
                return sXPath.select(contextNode);
            }
        } catch (XPathExpressionException e)
        {
            System.err.println("invalid xpath {}" + relativeXPath);
            return Collections.emptyList();
        }
    }

    public static List<Element> getElementMatch(
            Element contextNode,
            String relativeXPath,
            Map<String, String> nsPrefixURIMap)
    {
        List<Node> nodes = getMatch(contextNode, relativeXPath, nsPrefixURIMap, false);
        List<Element> elements = new ArrayList<Element>(nodes.size());
        for (Node node : nodes)
        {
            if(node instanceof Element)
            {
                elements.add((Element) node);
            }
        }
        return elements;
    }

    public static String getMessage(JAXBException e)
    {
        String ret = e.getMessage();
        if(ret == null && e.getLinkedException() != null)
        {
            ret = e.getLinkedException().getMessage();
        }
        return ret;
    }

    public static JAXBException convert(JAXBException e)
    {
        return new JAXBException(getMessage(e), e.getLinkedException());
    }

}
