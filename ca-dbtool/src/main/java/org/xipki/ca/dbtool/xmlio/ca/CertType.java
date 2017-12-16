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
 * @since 2.0.0
 */

public class CertType extends IdentifidDbObjectType {

    public static final String TAG_PARENT = "certs";

    public static final String TAG_ROOT = "cert";

    public static final String TAG_ART = "art";

    public static final String TAG_CAID = "caId";

    /**
     * certificate serial number.
     */
    public static final String TAG_SN = "sn";

    /**
     * certificate profile id.
     */
    public static final String TAG_PID = "pid";

    /**
     * requestor id.
     */
    public static final String TAG_RID = "rid";

    /**
     * first 8 bytes of the SHA1 sum of the requested subject.
     */
    public static final String TAG_FP_RS = "fpRs";

    /**
     * requested subject, if differs from the one in certificate.
     */
    public static final String TAG_RS = "rs";

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

    public static final String TAG_EE = "ee";

    public static final String TAG_UID = "uid";

    /**
     * base64 encoded transaction id.
     */
    public static final String TAG_TID = "tid";

    public static final String TAG_REQ_TYPE = "reqType";

    private String file;

    private Integer art;

    private Integer caId;

    private String sn;

    private Integer pid;

    private Integer rid;

    private Boolean ee;

    private Long update;

    private Boolean rev;

    private Integer rr;

    private Long rt;

    private Long rit;

    private Integer uid;

    private String tid;

    private Integer reqType;

    private Long fpRs;

    private String rs;

    public Integer art() {
        return art;
    }

    public void setArt(final Integer art) {
        this.art = art;
    }

    public Integer caId() {
        return caId;
    }

    public void setCaId(final Integer caId) {
        this.caId = caId;
    }

    public String sn() {
        return sn;
    }

    public void setSn(final String sn) {
        this.sn = sn;
    }

    public Boolean isEe() {
        return ee;
    }

    public void setEe(final Boolean ee) {
        this.ee = ee;
    }

    public Integer pid() {
        return pid;
    }

    public void setPid(final Integer pid) {
        this.pid = pid;
    }

    public Integer rid() {
        return rid;
    }

    public void setRid(final Integer rid) {
        this.rid = rid;
    }

    public Long update() {
        return update;
    }

    public void setUpdate(final Long update) {
        this.update = update;
    }

    public Boolean rev() {
        return rev;
    }

    public void setRev(final Boolean rev) {
        this.rev = rev;
    }

    public Integer rr() {
        return rr;
    }

    public void setRr(final Integer rr) {
        this.rr = rr;
    }

    public Long rt() {
        return rt;
    }

    public void setRt(final Long rt) {
        this.rt = rt;
    }

    public Long rit() {
        return rit;
    }

    public void setRit(final Long rit) {
        this.rit = rit;
    }

    public String tid() {
        return tid;
    }

    public void setTid(final String tid) {
        this.tid = tid;
    }

    public Integer reqType() {
        return reqType;
    }

    public void setReqType(final Integer reqType) {
        this.reqType = reqType;
    }

    public Long fpRs() {
        return fpRs;
    }

    public void setFpRs(final Long fpRs) {
        this.fpRs = fpRs;
    }

    public String rs() {
        return rs;
    }

    public void setRs(final String rs) {
        this.rs = rs;
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

        assertNotNull(TAG_ART, art);
        assertNotNull(TAG_CAID, caId);
        assertNotNull(TAG_EE, ee);
        assertNotBlank(TAG_FILE, file);
        assertNotNull(TAG_PID, pid);
        assertNotNull(TAG_REQ_TYPE, reqType);
        assertNotNull(TAG_REV, rev);
        assertNotNull(TAG_RID, rid);
        assertNotBlank(TAG_SN, sn);
        assertNotNull(TAG_UPDATE, update);
        if (rev) {
            assertNotNull(TAG_RR, rr);
            assertNotNull(TAG_RT, rt);
        }
    }

    public Integer uid() {
        return uid;
    }

    public void setUid(final Integer uid) {
        this.uid = uid;
    }

    @Override
    public void writeTo(final DbiXmlWriter writer)
            throws InvalidDataObjectException, XMLStreamException {
        ParamUtil.requireNonNull("writer", writer);

        validate();

        writer.writeStartElement(TAG_ROOT);
        writeIfNotNull(writer, TAG_ID, id());
        writeIfNotNull(writer, TAG_ART, art);
        writeIfNotNull(writer, TAG_CAID, caId);
        writeIfNotNull(writer, TAG_SN, sn);
        writeIfNotNull(writer, TAG_PID, pid);
        writeIfNotNull(writer, TAG_RID, rid);
        writeIfNotNull(writer, TAG_EE, ee);
        writeIfNotNull(writer, TAG_UPDATE, update);
        writeIfNotNull(writer, TAG_REV, rev);
        writeIfNotNull(writer, TAG_RR, rr);
        writeIfNotNull(writer, TAG_RT, rt);
        writeIfNotNull(writer, TAG_RIT, rit);
        writeIfNotNull(writer, TAG_UID, uid);
        writeIfNotNull(writer, TAG_TID, tid);
        writeIfNotNull(writer, TAG_REQ_TYPE, reqType);
        writeIfNotNull(writer, TAG_FP_RS, fpRs);
        writeIfNotNull(writer, TAG_RS, rs);
        writeIfNotNull(writer, TAG_FILE, file);
        writer.writeEndElement();
        writer.writeNewline();
    }

}
