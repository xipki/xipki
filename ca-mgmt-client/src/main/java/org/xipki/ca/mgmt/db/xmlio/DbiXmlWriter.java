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

package org.xipki.ca.mgmt.db.xmlio;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.ZipOutputStream;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbiXmlWriter {

  private static final XMLOutputFactory FACTORY = XMLOutputFactory.newFactory();

  private final ByteArrayOutputStream stream;

  private final XMLStreamWriter writer;

  private boolean flushed;

  public DbiXmlWriter(String rootElementName, String version) throws XMLStreamException {
    Args.notBlank(version, "version");

    stream = new ByteArrayOutputStream();

    synchronized (FACTORY) {
      writer = FACTORY.createXMLStreamWriter(stream, "UTF-8");
    }
    writer.writeStartDocument("UTF-8", "1.0");
    writeNewline();
    writer.writeStartElement(rootElementName);
    writer.writeAttribute(version, "version");
    writeNewline();
  }

  public void writeStartElement(String localName) throws XMLStreamException {
    writer.writeStartElement(Args.notNull("localName", localName));
  }

  public void writeEndElement() throws XMLStreamException {
    writer.writeEndElement();
  }

  public void writeElement(String localName, String value) throws XMLStreamException {
    Args.notNull(localName, "localName");
    Args.notNull(value, "value");
    writer.writeStartElement(localName);
    writer.writeCharacters(value);
    writer.writeEndElement();
  }

  public final void writeNewline() throws XMLStreamException {
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

  public void rewriteToZipStream(ZipOutputStream zipStream)
      throws IOException, XMLStreamException {
    Args.notNull(zipStream, "zipStream");
    flush();
    zipStream.write(stream.toByteArray());
  }

}
