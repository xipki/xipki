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
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CaUserType extends IdentifidDbObjectType {

    public static final String TAG_PARENT = "causers";

    public static final String TAG_ROOT = "causer";

    public static final String TAG_CA_ID = "caId";

    public static final String TAG_UID = "uid";

    public static final String TAG_PERMISSION = "permission";

    public static final String TAG_PROFILES = "profiles";

    private Integer caId;

    private Integer uid;

    private Integer permission;

    private String profiles;

    public Integer aId() {
        return caId;
    }

    public void setCaId(Integer caId) {
        this.caId = caId;
    }

    public Integer uid() {
        return uid;
    }

    public void setUid(Integer uid) {
        this.uid = uid;
    }

    public Integer permission() {
        return permission;
    }

    public void setPermission(Integer permission) {
        this.permission = permission;
    }

    public String profiles() {
        return profiles;
    }

    public void setProfiles(String profiles) {
        this.profiles = profiles;
    }

    @Override
    public void validate() throws InvalidDataObjectException {
        super.validate();
        assertNotNull(TAG_CA_ID, caId);
        assertNotNull(TAG_UID, uid);
    }

    @Override
    public void writeTo(final DbiXmlWriter writer)
            throws InvalidDataObjectException, XMLStreamException {
        ParamUtil.requireNonNull("writer", writer);
        validate();

        writer.writeStartElement(TAG_ROOT);
        writeIfNotNull(writer, TAG_ID, id());
        writeIfNotNull(writer, TAG_CA_ID, caId);
        writeIfNotNull(writer, TAG_UID, uid);
        writeIfNotNull(writer, TAG_PERMISSION, permission);
        writeIfNotNull(writer, TAG_PROFILES, profiles);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
