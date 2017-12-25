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
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertsReader extends DbiXmlReader {

    public CertsReader(final InputStream xmlStream)
            throws XMLStreamException, InvalidDataObjectException {
        super(CertType.TAG_PARENT, xmlStream);
    }

    @Override
    protected DbDataObject retrieveNext() throws InvalidDataObjectException, XMLStreamException {
        CertType ret = null;

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
                if (CertType.TAG_ROOT.equals(reader.getLocalName())) {
                    ret = new CertType();
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
                case CertType.TAG_ROOT:
                    ret.validate();
                    return ret;
                case CertType.TAG_ART:
                    ret.setArt(Integer.parseInt(tagContent));
                    break;
                case CertType.TAG_CAID:
                    ret.setCaId(Integer.parseInt(tagContent));
                    break;
                case CertType.TAG_FILE:
                    ret.setFile(tagContent);
                    break;
                case CertType.TAG_EE:
                    ret.setEe(Boolean.parseBoolean(tagContent));
                    break;
                case CertType.TAG_FP_RS:
                    ret.setFpRs(Long.parseLong(tagContent));
                    break;
                case CertType.TAG_ID:
                    ret.setId(Long.parseLong(tagContent));
                    break;
                case CertType.TAG_PID:
                    ret.setPid(Integer.parseInt(tagContent));
                    break;
                case CertType.TAG_REQ_TYPE:
                    ret.setReqType(Integer.parseInt(tagContent));
                    break;
                case CertType.TAG_REV:
                    ret.setRev(Boolean.parseBoolean(tagContent));
                    break;
                case CertType.TAG_RID:
                    ret.setRid(Integer.parseInt(tagContent));
                    break;
                case CertType.TAG_RIT:
                    ret.setRit(Long.parseLong(tagContent));
                    break;
                case CertType.TAG_RR:
                    ret.setRr(Integer.parseInt(tagContent));
                    break;
                case CertType.TAG_RS:
                    ret.setRs(tagContent);
                    break;
                case CertType.TAG_RT:
                    ret.setRt(Long.parseLong(tagContent));
                    break;
                case CertType.TAG_SN:
                    ret.setSn(tagContent);
                    break;
                case CertType.TAG_TID:
                    ret.setTid(tagContent);
                    break;
                case CertType.TAG_UID:
                    ret.setUid(Integer.parseInt(tagContent));
                    break;
                case CertType.TAG_UPDATE:
                    ret.setUpdate(Long.parseLong(tagContent));
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
