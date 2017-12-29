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

import javax.xml.stream.XMLStreamException;

import org.xipki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.ca.dbtool.xmlio.IdentifidDbObjectType;
import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestCertType extends IdentifidDbObjectType {

    public static final String TAG_PARENT = "reqcerts";

    public static final String TAG_ROOT = "reqcert";

    public static final String TAG_RID = "rid";

    public static final String TAG_CID = "cid";

    private Long rid;

    private Long cid;

    public Long rid() {
        return rid;
    }

    public void setRid(long rid) {
        this.rid = rid;
    }

    public Long cid() {
        return cid;
    }

    public void setCid(long cid) {
        this.cid = cid;
    }

    @Override
    public void validate() throws InvalidDataObjectException {
        super.validate();
        assertNotNull(TAG_RID, rid);
        assertNotNull(TAG_CID, cid);
    }

    @Override
    public void writeTo(DbiXmlWriter writer) throws InvalidDataObjectException, XMLStreamException {
        ParamUtil.requireNonNull("writer", writer);
        validate();

        writer.writeStartElement(TAG_ROOT);
        writeIfNotNull(writer, TAG_ID, id());
        writeIfNotNull(writer, TAG_RID, rid);
        writeIfNotNull(writer, TAG_CID, cid);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
