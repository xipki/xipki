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

package org.xipki.ca.dbtool.xmlio.ca;

import java.io.InputStream;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.xipki.ca.dbtool.xmlio.DbDataObject;
import org.xipki.ca.dbtool.xmlio.DbiXmlReader;
import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestCertsReader extends DbiXmlReader {

  public RequestCertsReader(InputStream xmlStream)
      throws XMLStreamException, InvalidDataObjectException {
    super(RequestCertType.TAG_PARENT, xmlStream);
  }

  @Override
  protected DbDataObject retrieveNext() throws InvalidDataObjectException, XMLStreamException {
    RequestCertType ret = null;

    StringBuilder buffer = new StringBuilder();
    int lastEvent = -1;

    while (reader.hasNext()) {
      int event = reader.next();
      String tagContent = null;

      if (event != XMLStreamConstants.CHARACTERS) {
        tagContent = buffer.toString();

        if (lastEvent == XMLStreamConstants.CHARACTERS) {
          buffer.delete(0, buffer.length());
        }
      }

      lastEvent = event;

      if (event == XMLStreamConstants.START_ELEMENT) {
        if (RequestCertType.TAG_ROOT.equals(reader.getLocalName())) {
          ret = new RequestCertType();
        }
      } else if (event == XMLStreamConstants.CHARACTERS) {
        buffer.append(reader.getText());
      } else if (event == XMLStreamConstants.END_ELEMENT) {
        if (ret == null) {
          continue;
        }

        switch (reader.getLocalName()) {
          case RequestCertType.TAG_ROOT:
            ret.validate();
            return ret;
          case RequestCertType.TAG_ID:
            ret.setId(parseLong(tagContent));
            break;
          case RequestCertType.TAG_RID:
            ret.setRid(parseLong(tagContent));
            break;
          case RequestCertType.TAG_CID:
            ret.setCid(parseLong(tagContent));
            break;
          default:
            break;
        } // end switch (reader.getLocalName())
      } // end if (event)
    } // end while

    return null;
  } // method retrieveNext

}
