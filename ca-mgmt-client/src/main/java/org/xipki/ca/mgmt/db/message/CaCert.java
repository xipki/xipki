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

package org.xipki.ca.mgmt.db.message;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaCert extends IdentifidDbObject {

  public static class Certs extends ValidatableConf {

    private List<CaCert> certs;

    public List<CaCert> getCerts() {
      if (certs == null) {
        certs = new LinkedList<>();
      }
      return certs;
    }

    public void setCerts(List<CaCert> certs) {
      this.certs = certs;
    }

    public void add(CaCert cert) {
      getCerts().add(cert);
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(certs);
    }

  }

  private String file;

  private Integer caId;

  /**
   * certificate serial number.
   */
  private String sn;

  /**
   * certificate profile id.
   */
  private Integer pid;

  /**
   * requestor id.
   */
  private Integer rid;

  private Boolean ee;

  private Long update;

  /**
   * whether revoked.
   */
  private Integer rev;

  /**
   * revocation reason.
   */
  private Integer rr;

  /**
   * revocation time.
   */
  private Long rt;

  /**
   * revocation invalidity time.
   */
  private Long rit;

  private Integer uid;

  /**
   * base64 encoded transaction id.
   */
  private String tid;

  private Integer reqType;

  /**
   * first 8 bytes of the SHA1 sum of the requested subject.
   */
  private Long fpRs;

  /**
   * requested subject, if differs from the one in certificate.
   */
  private String rs;

  public Integer getCaId() {
    return caId;
  }

  public void setCaId(Integer caId) {
    this.caId = caId;
  }

  public String getSn() {
    return sn;
  }

  public void setSn(String sn) {
    this.sn = sn;
  }

  public Boolean isEe() {
    return ee;
  }

  public void setEe(Boolean ee) {
    this.ee = ee;
  }

  public Integer getPid() {
    return pid;
  }

  public void setPid(Integer pid) {
    this.pid = pid;
  }

  public Integer getRid() {
    return rid;
  }

  public void setRid(Integer rid) {
    this.rid = rid;
  }

  public Long getUpdate() {
    return update;
  }

  public void setUpdate(Long update) {
    this.update = update;
  }

  public Integer getRev() {
    return rev;
  }

  public void setRev(Integer rev) {
    this.rev = rev;
  }

  public Integer getRr() {
    return rr;
  }

  public void setRr(Integer rr) {
    this.rr = rr;
  }

  public Long getRt() {
    return rt;
  }

  public void setRt(Long rt) {
    this.rt = rt;
  }

  public Long getRit() {
    return rit;
  }

  public void setRit(Long rit) {
    this.rit = rit;
  }

  public String getTid() {
    return tid;
  }

  public void setTid(String tid) {
    this.tid = tid;
  }

  public Integer getReqType() {
    return reqType;
  }

  public void setReqType(Integer reqType) {
    this.reqType = reqType;
  }

  public Long getFpRs() {
    return fpRs;
  }

  public void setFpRs(Long fpRs) {
    this.fpRs = fpRs;
  }

  public String getRs() {
    return rs;
  }

  public void setRs(String rs) {
    this.rs = rs;
  }

  public String getFile() {
    return file;
  }

  public void setFile(String file) {
    this.file = file;
  }

  public Integer getUid() {
    return uid;
  }

  public void setUid(Integer uid) {
    this.uid = uid;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();

    notNull(caId, "caId");
    notNull(ee, "ee");
    notEmpty(file, "file");
    notNull(pid, "pid");
    notNull(reqType, "reqType");
    notNull(rev, "rev");
    notNull(rid, "rid");
    notEmpty(sn, "sn");
    notNull(update, "update");
    if (rev != null && rev.intValue() == 1) {
      notNull(rr, "rr");
      notNull(rt, "rt");
    }
  }

}
