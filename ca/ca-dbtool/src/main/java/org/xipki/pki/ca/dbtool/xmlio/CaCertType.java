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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
 * @since 2.0
 */

public class CaCertType extends DbDataObject {

  public static final String TAG_ROOT = "cert";

  public static final String TAG_id = "id";

  private Integer id;

  public static final String TAG_art = "art";

  private Integer art;

  public static final String TAG_caId = "caId";

  private Integer caId;

  /**
   * certificate serial number
   */
  public static final String TAG_sn = "sn";

  private String sn;

  /**
   * certificate profile id
   */
  public static final String TAG_pid = "pid";

  private Integer pid;

  /**
   * requestor id
   */
  public static final String TAG_rid = "rid";

  private Integer rid;

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

  public static final String TAG_user = "user";

  private String user;

  /**
   * base64 encoded transaction id
   */
  public static final String TAG_tid = "tid";

  private String tid;

  public static final String TAG_reqType = "reqType";

  private Integer reqType;

  /**
   * first 8 bytes of the SHA1 sum of the requested subject
   */
  public static final String TAG_fpRs = "fpRs";

  private Long fpRs;

  /**
   * requested subject, if differs from the one in certificate
   */
  public static final String TAG_rs = "rs";

  private String rs;

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

  public Integer getArt() {
    return art;
  }

  public void setArt(
      final Integer art) {
    this.art = art;
  }

  public Integer getCaId() {
    return caId;
  }

  public void setCaId(
      final Integer caId) {
    this.caId = caId;
  }

  public String getSn() {
    return sn;
  }

  public void setSn(
      final String sn) {
    this.sn = sn;
  }

  public Integer getPid() {
    return pid;
  }

  public void setPid(
      final Integer pid) {
    this.pid = pid;
  }

  public Integer getRid() {
    return rid;
  }

  public void setRid(
      final Integer rid) {
    this.rid = rid;
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

  public String getTid() {
    return tid;
  }

  public void setTid(
      final String tid) {
    this.tid = tid;
  }

  public Integer getReqType() {
    return reqType;
  }

  public void setReqType(
      final Integer reqType) {
    this.reqType = reqType;
  }

  public Long getFpRs() {
    return fpRs;
  }

  public void setFpRs(
      final Long fpRs) {
    this.fpRs = fpRs;
  }

  public String getRs() {
    return rs;
  }

  public void setRs(
      final String rs) {
    this.rs = rs;
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
    assertNotNull("art", art);
    assertNotNull("caId", caId);
    assertNotBlank("sn", sn);
    assertNotNull("pid", pid);
    assertNotNull("update", update);
    assertNotNull("rev", rev);
    if (rev) {
      assertNotNull("rr", rr);
      assertNotNull("rt", rt);
    }

    assertNotNull("reqType", reqType);
    if (rs != null) {
      assertNotNull("fpRs", fpRs);
      assertNotBlank("rs", rs);
    }
    assertNotBlank("file", file);
  }

  public String getUser() {
    return user;
  }

  public void setUser(
      final String user) {
    this.user = user;
  }

  @Override
  public void writeTo(
      final DbiXmlWriter writer)
  throws InvalidDataObjectException, XMLStreamException {
    validate();

    writer.writeStartElement(TAG_ROOT);
    writeIfNotNull(writer, TAG_id, id);
    writeIfNotNull(writer, TAG_art, art);
    writeIfNotNull(writer, TAG_caId, caId);
    writeIfNotNull(writer, TAG_sn, sn);
    writeIfNotNull(writer, TAG_pid, pid);
    writeIfNotNull(writer, TAG_rid, rid);
    writeIfNotNull(writer, TAG_update, update);
    writeIfNotNull(writer, TAG_rev, rev);
    writeIfNotNull(writer, TAG_rr, rr);
    writeIfNotNull(writer, TAG_rt, rt);
    writeIfNotNull(writer, TAG_rit, rit);
    writeIfNotNull(writer, TAG_user, user);
    writeIfNotNull(writer, TAG_tid, tid);
    writeIfNotNull(writer, TAG_reqType, reqType);
    writeIfNotNull(writer, TAG_fpRs, fpRs);
    writeIfNotNull(writer, TAG_rs, rs);
    writeIfNotNull(writer, TAG_file, file);
    writer.writeEndElement();
    writer.writeNewline();
  }

}
