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
 *
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

package org.xipki.pki.ca.dbtool.xmlio;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.ZipOutputStream;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.xipki.commons.common.util.ParamUtil;

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

    public DbiXmlWriter(
            final String rootElementName,
            final String version)
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

    public String getRootElementName() {
        return rootElementName;
    }

    public void writeStartElement(
            final String localName)
    throws XMLStreamException {
        ParamUtil.requireNonNull("localName", localName);
        writer.writeStartElement(localName);
    }

    public void writeEndElement()
    throws XMLStreamException {
        writer.writeEndElement();
    }

    public void writeElement(
            final String localName,
            final String value)
    throws XMLStreamException {
        ParamUtil.requireNonNull("localName", localName);
        ParamUtil.requireNonNull("value", value);
        writer.writeStartElement(localName);
        writer.writeCharacters(value);
        writer.writeEndElement();
    }

    public void writeNewline()
    throws XMLStreamException {
        writer.writeCharacters("\n");
    }

    public void flush()
    throws IOException, XMLStreamException {
        if (flushed) {
            return;
        }

        writer.writeEndElement();
        writer.writeEndDocument();

        stream.flush();
        flushed = true;
    }

    public void rewriteToZipStream(
            final ZipOutputStream zipStream)
    throws IOException, XMLStreamException {
        ParamUtil.requireNonNull("zipStream", zipStream);
        flush();
        zipStream.write(stream.toByteArray());
    }

}
