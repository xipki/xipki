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

package org.xipki.ca.dbtool.xmlio.ca;

import java.io.InputStream;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.xipki.ca.dbtool.xmlio.DbDataObject;
import org.xipki.ca.dbtool.xmlio.DbiXmlReader;
import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CaUsersReader extends DbiXmlReader {

    public CaUsersReader(final InputStream xmlStream)
            throws XMLStreamException, InvalidDataObjectException {
        super(CaUserType.TAG_PARENT, xmlStream);
    }

    @Override
    protected DbDataObject retrieveNext() throws InvalidDataObjectException, XMLStreamException {
        CaUserType ret = null;

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

            switch (event) {
            case XMLStreamConstants.START_ELEMENT:
                if (RequestCertType.TAG_ROOT.equals(reader.getLocalName())) {
                    ret = new CaUserType();
                }
                break;
            case XMLStreamConstants.CHARACTERS:
                buffer.append(reader.getText());
                break;
            case XMLStreamConstants.END_ELEMENT:
                if (ret == null) {
                    break;
                }

                switch (reader.getLocalName()) {
                case CaUserType.TAG_ROOT:
                    ret.validate();
                    return ret;
                case CaUserType.TAG_CA_ID:
                    ret.setCaId(Integer.parseInt(tagContent));
                    break;
                case CertType.TAG_ID:
                    ret.setId(Long.parseLong(tagContent));
                    break;
                case CaUserType.TAG_UID:
                    ret.setUid(Integer.parseInt(tagContent));
                    break;
                case CaUserType.TAG_PERMISSION:
                    ret.setPermission(Integer.parseInt(tagContent));
                    break;
                case CaUserType.TAG_PROFILES:
                    ret.setProfiles(tagContent);
                    break;
                default:
                    break;
                } // end switch (reader.getLocalName())
                break;
            default:
                break;
            } // end switch (event)
        } // end while

        return null;
    } // method retrieveNext

}
