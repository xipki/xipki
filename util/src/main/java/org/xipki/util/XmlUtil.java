/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.util;

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
 * TODO.
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
      throw new ExceptionInInitializerError(new Exception(
          "could not initialize the XMLDocumentBuilder", ex));
    }
    if (builder != null) {
      document = builder.newDocument();
    }
  }

  private XmlUtil() {
  }

  public static Element createElement(String namespace, String localPart, String value) {
    if (document == null) {
      throw new IllegalStateException("XMLDocumentBuilder must not be initialized");
    }
    Args.notBlank(localPart, "localPart");
    Element element = document.createElementNS(namespace, "ns:" + localPart);
    if (StringUtil.isNotBlank(value)) {
      element.appendChild(document.createTextNode(value));
    }
    return element;
  }

  public static Element getDocumentElment(byte[] xmlFragement) throws IOException, SAXException {
    Args.notNull(xmlFragement, "xmlFragement");
    Document doc = builder.parse(new ByteArrayInputStream(xmlFragement));
    return doc.getDocumentElement();
  }

  public static Calendar getCalendar(Date dateAndTime) {
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

  public static XMLGregorianCalendar getXmlDate(Calendar calendar) {
    Args.notNull(calendar, "calendar");
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

  public static XMLGregorianCalendar getXmlDate(Date dateAndTime) {
    Args.notNull(dateAndTime, "dateAndTime");
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

  public static String getValueOfFirstElementChild(Element element, String namespace,
      String localname) {
    Node node = getFirstElementChild(element, namespace, localname);
    return (node == null) ? null : getNodeValue(node);
  }

  public static String getNodeValue(Node node) {
    Args.notNull(node, "node");
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

  public static Element getFirstElementChild(Element element, String namespace, String localname) {
    Args.notNull(element, "element");
    Args.notBlank(localname, "localname");
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
   * TODO.
   * @param element context element.
   * @param namespace namespace of the expected element. Set it to {@code null} if namespace
   *     will not be evaluated.
   * @param localname localname of the expected element.
   * @return List of the expected children element. If no match children could be found, empty
   *     list will be returned.
   */
  public static List<Element> getElementChilden(Element element, String namespace,
      String localname) {
    Args.notNull(element, "element");
    Args.notBlank(localname, "localname");
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

  public static List<Element> getAllElementsWithAttrId(Element element, String namespace) {
    Args.notNull(element, "element");
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

  private static void addAllElementsWithAttrId(List<Element> list, Element element,
      String namespace) {
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

  private static boolean elementHasId(Element element, String namespace) {
    return element.hasAttributeNS(namespace, "Id");
  }

  private static boolean match(Node node, String namespace, String localname) {
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

  public static String getValueOfFirstMatch(Element contextNode, String relativeXpath,
      Map<String, String> nsPrefixUriMap) {
    Node node = getFirstMatch(contextNode, relativeXpath, nsPrefixUriMap);
    return (node == null) ? null : getNodeValue(node);
  }

  public static Node getFirstMatch(Element contextNode, String relativeXPath,
      Map<String, String> nsPrefixUriMap) {
    List<Node> nodes = getMatch(contextNode, relativeXPath, nsPrefixUriMap, true);
    return CollectionUtil.isEmpty(nodes) ? null : nodes.get(0);
  }

  public static List<Node> getMatch(Element contextNode, String relativeXPath,
      Map<String, String> nsPrefixUriMap) {
    return getMatch(contextNode, relativeXPath, nsPrefixUriMap, false);
  }

  private static List<Node> getMatch(Element contextNode, String relativeXpath,
      Map<String, String> nsPrefixUriMap, boolean onlyFirstMatch) {
    try {
      SimpleXpath simpleXpath = new SimpleXpath(relativeXpath, nsPrefixUriMap);
      if (onlyFirstMatch) {
        Node node = simpleXpath.selectFirstMatch(contextNode);
        return (node == null) ? Collections.emptyList() : Arrays.asList(node);
      } else {
        return simpleXpath.select(contextNode);
      }
    } catch (XPathExpressionException ex) {
      System.err.println("invalid xpath {}" + relativeXpath);
      return Collections.emptyList();
    }
  }

  public static List<Element> getElementMatch(Element contextNode,
      String relativeXpath, Map<String, String> nsPrefixUriMap) {
    List<Node> nodes = getMatch(contextNode, relativeXpath, nsPrefixUriMap, false);
    List<Element> elements = new ArrayList<Element>(nodes.size());
    for (Node node : nodes) {
      if (node instanceof Element) {
        elements.add((Element) node);
      }
    }
    return elements;
  }

  public static String getMessage(JAXBException ex) {
    Args.notNull(ex, "ex");
    String ret = ex.getMessage();
    if (ret == null && ex.getLinkedException() != null) {
      ret = ex.getLinkedException().getMessage();
    }
    return ret;
  }

  public static JAXBException convert(JAXBException ex) {
    Args.notNull(ex, "ex");
    return new JAXBException(getMessage(ex), ex.getLinkedException());
  }

}
