/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.pki.ca.dbtool.xmlio.ca;

import javax.xml.stream.XMLStreamException;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.pki.ca.dbtool.xmlio.IdentifidDbObjectType;
import org.xipki.pki.ca.dbtool.xmlio.InvalidDataObjectException;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CaUserType extends IdentifidDbObjectType {

    public static final String TAG_PARENT = "causers";

    public static final String TAG_ROOT = "causer";

    public static final String TAG_CA_ID = "caId";

    public static final String TAG_UID = "uid";

    public static final String TAG_PERMISSIONS = "permissions";

    public static final String TAG_PROFILES = "profiles";

    private Integer caId;

    private Integer uid;

    private String permissions;

    private String profiles;

    public Integer getCaId() {
        return caId;
    }

    public void setCaId(Integer caId) {
        this.caId = caId;
    }

    public Integer getUid() {
        return uid;
    }

    public void setUid(Integer uid) {
        this.uid = uid;
    }

    public String getPermissions() {
        return permissions;
    }

    public void setPermissions(String permissions) {
        this.permissions = permissions;
    }

    public String getProfiles() {
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
        writeIfNotNull(writer, TAG_ID, getId());
        writeIfNotNull(writer, TAG_CA_ID, caId);
        writeIfNotNull(writer, TAG_UID, uid);
        writeIfNotNull(writer, TAG_PERMISSIONS, permissions);
        writeIfNotNull(writer, TAG_PROFILES, profiles);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
