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

public class OcspCertType extends DbDataObject {

    public static final String TAG_ROOT = "cert";

    public static final String TAG_id = "id";

    private Integer id;

    /**
     * issuer id
     */
    public static final String TAG_iid = "iid";

    private Integer iid;

    /**
     * certificate serial number
     */
    public static final String TAG_sn = "sn";

    private String sn;

    public static final String TAG_update = "update";

    private Long update;

    /**
     * whether revoked
     */
    public static final String TAG_rev = "rev";

    private Boolean rev;

    /**
     * revocation reason
     */
    public static final String TAG_rr = "rr";

    private Integer rr;

    /**
     * revocation time
     */
    public static final String TAG_rt = "rt";

    private Long rt;

    /**
     * revocation invalidity time
     */
    public static final String TAG_rit = "rit";

    private Long rit;

    /**
     * certificate profile name
     */
    public static final String TAG_profile = "profile";

    private String profile;

    /**
     * file name of the certificate
     */
    public static final String TAG_file = "file";

    private String file;

    public Integer getId() {
        return id;
    }

    public void setId(
            final Integer id) {
        this.id = id;
    }

    public Integer getIid() {
        return iid;
    }

    public void setIid(
            final Integer iid) {
        this.iid = iid;
    }

    public String getSn() {
        return sn;
    }

    public void setSn(
            final String sn) {
        this.sn = sn;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(
            final String profile) {
        this.profile = profile;
    }

    public Long getUpdate() {
        return update;
    }

    public void setUpdate(
            final Long update) {
        this.update = update;
    }

    public Boolean getRev() {
        return rev;
    }

    public void setRev(
            final Boolean rev) {
        this.rev = rev;
    }

    public Integer getRr() {
        return rr;
    }

    public void setRr(
            final Integer rr) {
        this.rr = rr;
    }

    public Long getRt() {
        return rt;
    }

    public void setRt(
            final Long rt) {
        this.rt = rt;
    }

    public Long getRit() {
        return rit;
    }

    public void setRit(
            final Long rit) {
        this.rit = rit;
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
        assertNotNull("iid", iid);
        assertNotBlank("sn", sn);
        assertNotNull("update", update);
        assertNotNull("rev", rev);
        if (rev) {
            assertNotNull("rr", rr);
            assertNotNull("rt", rt);
        }

        assertNotBlank("file", file);
    }

    @Override
    public void writeTo(
            final DbiXmlWriter writer)
    throws InvalidDataObjectException, XMLStreamException {
        validate();

        writer.writeStartElement(TAG_ROOT);
        writeIfNotNull(writer, TAG_id, id);
        writeIfNotNull(writer, TAG_iid, iid);
        writeIfNotNull(writer, TAG_sn, sn);
        writeIfNotNull(writer, TAG_update, update);
        writeIfNotNull(writer, TAG_rev, rev);
        writeIfNotNull(writer, TAG_rr, rr);
        writeIfNotNull(writer, TAG_rt, rt);
        writeIfNotNull(writer, TAG_rit, rit);
        writeIfNotNull(writer, TAG_profile, profile);
        writeIfNotNull(writer, TAG_file, file);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
