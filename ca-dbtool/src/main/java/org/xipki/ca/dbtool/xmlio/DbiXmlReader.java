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

package org.xipki.ca.dbtool.xmlio;

import java.io.InputStream;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class DbiXmlReader {

    protected final XMLStreamReader reader;

    private final XMLInputFactory factory = XMLInputFactory.newInstance();

    private final String rootElementName;

    private DbDataObject next;

    public DbiXmlReader(final String rootElementName, final InputStream xmlStream)
            throws XMLStreamException, InvalidDataObjectException {
        this.rootElementName = ParamUtil.requireNonBlank("rootElementName", rootElementName);
        ParamUtil.requireNonNull("xmlStream", xmlStream);

        synchronized (factory) {
            reader = factory.createXMLStreamReader(xmlStream);
        }

        String thisRootElement = null;
        while (reader.hasNext()) {
            int event = reader.next();

            if (event == XMLStreamConstants.START_ELEMENT) {
                thisRootElement = reader.getLocalName();
                break;
            }
        }

        if (!this.rootElementName.equals(thisRootElement)) {
            throw new InvalidDataObjectException("the given XML stream does not have root element '"
                    + rootElementName + "', but '" + thisRootElement + "'");
        }

        this.next = retrieveNext();
    }

    public String rootElementName() {
        return rootElementName;
    }

    public boolean hasNext() {
        return next != null;
    }

    public DbDataObject next() throws InvalidDataObjectException, XMLStreamException {
        if (next == null) {
            throw new IllegalStateException("no more next element exists");
        }

        DbDataObject ret = next;
        next = retrieveNext();

        return ret;
    }

    protected abstract DbDataObject retrieveNext()
            throws InvalidDataObjectException, XMLStreamException;

}
