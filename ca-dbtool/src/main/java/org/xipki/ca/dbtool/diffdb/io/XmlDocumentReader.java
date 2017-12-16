/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.dbtool.diffdb.io;

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
import org.xipki.common.util.ParamUtil;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XmlDocumentReader {

    private final Document doc;

    private final XPathFactory xpathfactory;

    public XmlDocumentReader(final InputStream xmlStream, final boolean namespaceAware)
            throws ParserConfigurationException, SAXException, IOException {
        ParamUtil.requireNonNull("xmlStream", xmlStream);

        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        builderFactory.setNamespaceAware(namespaceAware);
        DocumentBuilder newDocumentBuilder = builderFactory.newDocumentBuilder();
        disableDtdValidation(newDocumentBuilder);
        doc = newDocumentBuilder.parse(xmlStream);

        xpathfactory = XPathFactory.newInstance();
    }

    private static void disableDtdValidation(final DocumentBuilder db) {
        db.setEntityResolver(new EntityResolver() {
            @Override
            public InputSource resolveEntity(final String publicId, final String systemId)
                    throws SAXException, IOException {
                return new InputSource(new StringReader(""));
            }
        });
    }

    public String value(final String xpathExpression) throws XPathExpressionException {
        ParamUtil.requireNonNull("xpathExpression", xpathExpression);
        Node node = getNode(xpathExpression);
        return (node != null) ? node.getFirstChild().getTextContent() : null;
    }

    private Node getNode(final String xpathExpression) throws XPathExpressionException {
        XPath xpath = xpathfactory.newXPath();
        XPathExpression xpathE = xpath.compile(xpathExpression);
        NodeList nl = (NodeList) xpathE.evaluate(doc.getDocumentElement(), XPathConstants.NODESET);
        if (nl != null && nl.getLength() > 0) {
            return nl.item(0);
        }

        return null;
    }

}
