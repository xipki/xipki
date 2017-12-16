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

import javax.xml.stream.XMLStreamException;

import org.xipki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.ca.dbtool.xmlio.IdentifidDbObjectType;
import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CrlType extends IdentifidDbObjectType {

    public static final String TAG_PARENT = "crls";

    public static final String TAG_ROOT = "crl";

    public static final String TAG_CAID = "caId";

    public static final String TAG_CRLNO = "crlNo";

    private Integer caId;

    private String crlNo;

    private String file;

    public Integer caId() {
        return caId;
    }

    public void setCaId(final Integer caId) {
        this.caId = caId;
    }

    public String crlNo() {
        return crlNo;
    }

    public void setCrlNo(final String crlNo) {
        this.crlNo = crlNo;
    }

    public String file() {
        return file;
    }

    public void setFile(final String file) {
        this.file = file;
    }

    @Override
    public void validate() throws InvalidDataObjectException {
        super.validate();
        assertNotNull(TAG_CAID, caId);
        assertNotBlank(TAG_CRLNO, crlNo);
        assertNotBlank(TAG_FILE, file);
    }

    @Override
    public void writeTo(final DbiXmlWriter writer)
            throws InvalidDataObjectException, XMLStreamException {
        validate();

        writer.writeStartElement(TAG_ROOT);
        writeIfNotNull(writer, TAG_ID, id());
        writeIfNotNull(writer, TAG_CAID, caId);
        writeIfNotNull(writer, TAG_CRLNO, crlNo);
        writeIfNotNull(writer, TAG_FILE, file);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
