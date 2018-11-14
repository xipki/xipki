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

import java.io.InputStream;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class DbiXmlReader {

  protected final XMLStreamReader reader;

  private final XMLInputFactory factory = XMLInputFactory.newInstance();

  private final String rootElementName;

  private DbDataObject next;

  public DbiXmlReader(String rootElementName, InputStream xmlStream)
      throws XMLStreamException, InvalidDataObjectException {
    this.rootElementName = Args.notBlank(rootElementName, "rootElementName");
    Args.notNull(xmlStream, "xmlStream");

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

  public String getRootElementName() {
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

  protected int parseInt(String str) {
    return Integer.parseInt(str);
  }

  protected long parseLong(String str) {
    return Long.parseLong(str);
  }

  protected boolean parseBoolean(String str) {
    return Boolean.parseBoolean(str);
  }

  protected abstract DbDataObject retrieveNext()
      throws InvalidDataObjectException, XMLStreamException;

}
