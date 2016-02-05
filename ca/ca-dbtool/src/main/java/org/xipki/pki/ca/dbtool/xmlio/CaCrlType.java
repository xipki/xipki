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

import javax.xml.stream.XMLStreamException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaCrlType extends DbDataObject {

    public static final String TAG_ROOT = "crl";

    public static final String TAG_ID = "id";

    public static final String TAG_CAID = "caId";

    public static final String TAG_CRLNO = "crlNo";

    public static final String TAG_FILE = "file";

    private Integer id;

    private Integer caId;

    private String crlNo;

    private String file;

    public Integer getId() {
        return id;
    }

    public void setId(
            final Integer id) {
        this.id = id;
    }

    public Integer getCaId() {
        return caId;
    }

    public void setCaId(
            final Integer caId) {
        this.caId = caId;
    }

    public String getCrlNo() {
        return crlNo;
    }

    public void setCrlNo(
            final String crlNo) {
        this.crlNo = crlNo;
    }

    public String getFile() {
        return file;
    }

    public void setFile(
            final String file) {
        this.file = file;
    }

    @Override
    public void validate()
    throws InvalidDataObjectException {
        assertNotNull("id", id);
        assertNotNull("caId", caId);
        assertNotBlank("crlNo", crlNo);
        assertNotBlank("file", file);
    }

    @Override
    public void writeTo(
            final DbiXmlWriter writer)
    throws InvalidDataObjectException, XMLStreamException {
        validate();

        writer.writeStartElement(TAG_ROOT);
        writeIfNotNull(writer, TAG_ID, id);
        writeIfNotNull(writer, TAG_CAID, caId);
        writeIfNotNull(writer, TAG_CRLNO, crlNo);
        writeIfNotNull(writer, TAG_FILE, file);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
