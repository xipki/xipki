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

package org.xipki.ca.dbtool.xmlio.ocsp;

import javax.xml.stream.XMLStreamException;

import org.xipki.ca.dbtool.xmlio.DbiXmlWriter;
import org.xipki.ca.dbtool.xmlio.IdentifidDbObjectType;
import org.xipki.ca.dbtool.xmlio.InvalidDataObjectException;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspCertType extends IdentifidDbObjectType {

    public static final String TAG_PARENT = "certs";

    public static final String TAG_ROOT = "cert";

    /**
     * issuer id.
     */
    public static final String TAG_IID = "iid";

    /**
     * certificate serial number.
     */
    public static final String TAG_SN = "sn";

    public static final String TAG_UPDATE = "update";

    /**
     * whether revoked.
     */
    public static final String TAG_REV = "rev";

    /**
     * revocation reason.
     */
    public static final String TAG_RR = "rr";

    /**
     * revocation time.
     */
    public static final String TAG_RT = "rt";

    /**
     * revocation invalidity time.
     */
    public static final String TAG_RIT = "rit";

    /**
     * certificate profile name.
     */
    public static final String TAG_PROFILE = "profile";

    private String file;

    private String profile;

    private Integer iid;

    private String sn;

    private Long update;

    private Boolean rev;

    private Integer rr;

    private Long rt;

    private Long rit;

    public Integer iid() {
        return iid;
    }

    public void setIid(Integer iid) {
        this.iid = iid;
    }

    public String sn() {
        return sn;
    }

    public void setSn(String sn) {
        this.sn = sn;
    }

    public String profile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public Long update() {
        return update;
    }

    public void setUpdate(Long update) {
        this.update = update;
    }

    public Boolean rev() {
        return rev;
    }

    public void setRev(Boolean rev) {
        this.rev = rev;
    }

    public Integer rr() {
        return rr;
    }

    public void setRr(Integer rr) {
        this.rr = rr;
    }

    public Long rt() {
        return rt;
    }

    public void setRt(Long rt) {
        this.rt = rt;
    }

    public Long rit() {
        return rit;
    }

    public void setRit(Long rit) {
        this.rit = rit;
    }

    public String file() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }

    @Override
    public void validate() throws InvalidDataObjectException {
        super.validate();
        assertNotNull(TAG_IID, iid);
        assertNotBlank(TAG_SN, sn);
        assertNotNull(TAG_UPDATE, update);
        assertNotNull(TAG_REV, rev);
        if (rev) {
            assertNotNull(TAG_RR, rr);
            assertNotNull(TAG_RT, rt);
        }

        assertNotBlank(TAG_FILE, file);
    }

    @Override
    public void writeTo(DbiXmlWriter writer) throws InvalidDataObjectException, XMLStreamException {
        ParamUtil.requireNonNull("writer", writer);

        validate();

        writer.writeStartElement(TAG_ROOT);
        writeIfNotNull(writer, TAG_ID, id());
        writeIfNotNull(writer, TAG_IID, iid);
        writeIfNotNull(writer, TAG_SN, sn);
        writeIfNotNull(writer, TAG_UPDATE, update);
        writeIfNotNull(writer, TAG_REV, rev);
        writeIfNotNull(writer, TAG_RR, rr);
        writeIfNotNull(writer, TAG_RT, rt);
        writeIfNotNull(writer, TAG_RIT, rit);
        writeIfNotNull(writer, TAG_PROFILE, profile);
        writeIfNotNull(writer, TAG_FILE, file);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
