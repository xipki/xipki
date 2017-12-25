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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.ZipOutputStream;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbiXmlWriter {

    private static final XMLOutputFactory FACTORY = XMLOutputFactory.newFactory();

    private final String rootElementName;

    private final ByteArrayOutputStream stream;

    private final XMLStreamWriter writer;

    private boolean flushed;

    public DbiXmlWriter(final String rootElementName, final String version)
            throws XMLStreamException {
        this.rootElementName = ParamUtil.requireNonBlank("rootElementName", rootElementName);
        ParamUtil.requireNonBlank("version", version);

        stream = new ByteArrayOutputStream();

        synchronized (FACTORY) {
            writer = FACTORY.createXMLStreamWriter(stream);
        }
        writer.writeStartDocument("UTF-8", "1.0");
        writeNewline();
        writer.writeStartElement(rootElementName);
        writer.writeAttribute("version", version);
        writeNewline();
    }

    public String rootElementName() {
        return rootElementName;
    }

    public void writeStartElement(final String localName) throws XMLStreamException {
        ParamUtil.requireNonNull("localName", localName);
        writer.writeStartElement(localName);
    }

    public void writeEndElement() throws XMLStreamException {
        writer.writeEndElement();
    }

    public void writeElement(final String localName, final String value) throws XMLStreamException {
        ParamUtil.requireNonNull("localName", localName);
        ParamUtil.requireNonNull("value", value);
        writer.writeStartElement(localName);
        writer.writeCharacters(value);
        writer.writeEndElement();
    }

    public void writeNewline() throws XMLStreamException {
        writer.writeCharacters("\n");
    }

    public void flush() throws IOException, XMLStreamException {
        if (flushed) {
            return;
        }

        writer.writeEndElement();
        writer.writeEndDocument();

        stream.flush();
        flushed = true;
    }

    public void rewriteToZipStream(final ZipOutputStream zipStream)
            throws IOException, XMLStreamException {
        ParamUtil.requireNonNull("zipStream", zipStream);
        flush();
        zipStream.write(stream.toByteArray());
    }

}
