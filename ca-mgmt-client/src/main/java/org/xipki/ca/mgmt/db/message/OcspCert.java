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
 * @since 2.0.0
 */

public class OcspCert extends IdentifidDbObject {

  public static class Certs extends ValidatableConf {

    private List<OcspCert> certs;

    public List<OcspCert> getCerts() {
      if (certs == null) {
        certs = new LinkedList<>();
      }
      return certs;
    }

    public void setCerts(List<OcspCert> certs) {
      this.certs = certs;
    }

    public void add(OcspCert cert) {
      getCerts().add(cert);
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(certs);
    }

  }

  private String hash;

  private Integer iid;

  private Long nafter;

  private Long nbefore;

  private Boolean rev;

  private Long rit;

  private Integer rr;

  private Long rt;

  private String sn;

  private String subject;

  private Long update;

  public String getHash() {
    return hash;
  }

  public void setHash(String hash) {
    this.hash = hash;
  }

  public Integer getIid() {
    return iid;
  }

  public void setIid(Integer iid) {
    this.iid = iid;
  }

  public Long getNafter() {
    return nafter;
  }

  public void setNafter(Long nafter) {
    this.nafter = nafter;
  }

  public Long getNbefore() {
    return nbefore;
  }

  public void setNbefore(Long nbefore) {
    this.nbefore = nbefore;
  }

  public Boolean getRev() {
    return rev;
  }

  public void setRev(Boolean rev) {
    this.rev = rev;
  }

  public Long getRit() {
    return rit;
  }

  public void setRit(Long rit) {
    this.rit = rit;
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

  public String getSn() {
    return sn;
  }

  public void setSn(String sn) {
    this.sn = sn;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  public Long getUpdate() {
    return update;
  }

  public void setUpdate(Long update) {
    this.update = update;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();

    notNull(iid, "iid");

    notEmpty(sn, "sn");
    notNull(rev, "rev");
    if (rev) {
      notNull(rr, "rr");
      notNull(rt, "rt");
    }
    notNull(update, "update");
  }

}
