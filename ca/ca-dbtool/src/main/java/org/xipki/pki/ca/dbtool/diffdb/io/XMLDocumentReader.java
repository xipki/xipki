/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.dbtool.diffdb.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XMLDocumentReader {

  private final Document doc;

  private final XPathFactory xpathfactory;

  public XMLDocumentReader(
      final InputStream xmlStream,
      final boolean namespaceAware)
  throws ParserConfigurationException, SAXException, IOException {
    DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
    builderFactory.setNamespaceAware(namespaceAware);
    DocumentBuilder newDocumentBuilder = builderFactory.newDocumentBuilder();
    disableDtdValidation(newDocumentBuilder);
    doc = newDocumentBuilder.parse(xmlStream);

    xpathfactory = XPathFactory.newInstance();
  }

  private static void disableDtdValidation(
      final DocumentBuilder db) {
    db.setEntityResolver(new EntityResolver() {
    @Override
    public InputSource resolveEntity(
        final String publicId,
        final String systemId)
    throws SAXException, IOException {
      return new InputSource(new StringReader(""));
    }
    });
  }

  public String getValue(
      final String xpathExpression)
  throws XPathExpressionException {
    Node n = getNode(xpathExpression);
    return (n != null)
        ? n.getFirstChild().getTextContent()
        : null;
  }

  private Node getNode(
      final String xpathExpression)
  throws XPathExpressionException {
    XPath xpath = xpathfactory.newXPath();
    XPathExpression xpathE = xpath.compile(xpathExpression);
    NodeList nl = (NodeList) xpathE.evaluate(doc.getDocumentElement(), XPathConstants.NODESET);
    if (nl != null && nl.getLength() > 0) {
      return nl.item(0);
    }

    return null;
  }

}
