/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.mgmt.db.port;

import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * OCSP CertStore.
 *
 * @author Lijun Liao
 */

public class OcspCertstore extends ValidatableConf {

  public static class Cert extends IdentifidDbObject {

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

    private Integer crlId;

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

    public Integer getCrlId() {
      return crlId;
    }

    public void setCrlId(Integer crlId) {
      this.crlId = crlId;
    }

    @Override
    public void validate() throws InvalidConfException {
      super.validate();

      notNull(iid, "iid");

      notBlank(sn, "sn");
      notNull(rev, "rev");
      if (rev) {
        notNull(rr, "rr");
        notNull(rt, "rt");
      }
      notNull(update, "update");
    }

  }

  public static class Certs extends ValidatableConf {

    private List<Cert> certs;

    public List<Cert> getCerts() {
      if (certs == null) {
        certs = new LinkedList<>();
      }
      return certs;
    }

    public void setCerts(List<Cert> certs) {
      this.certs = certs;
    }

    public void add(Cert cert) {
      getCerts().add(cert);
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(certs);
    }

  } // class Cert

  public static class Issuer extends ValidatableConf {

    private int id;

    private Integer crlId;

    private String certFile;

    private String revInfo;

    @Override
    public void validate() throws InvalidConfException {
      notBlank(certFile, "certFile");
    }

    public int getId() {
      return id;
    }

    public void setId(int id) {
      this.id = id;
    }

    public String getCertFile() {
      return certFile;
    }

    public void setCertFile(String certFile) {
      this.certFile = certFile;
    }

    public String getRevInfo() {
      return revInfo;
    }

    public void setRevInfo(String revInfo) {
      this.revInfo = revInfo;
    }

    public Integer getCrlId() {
      return crlId;
    }

    public void setCrlId(Integer crlId) {
      this.crlId = crlId;
    }

  } // class Issuer

  public static class CrlInfo extends ValidatableConf {

    private int id;

    private String name;

    private String info;

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notBlank(info, "info");
    }

    public int getId() {
      return id;
    }

    public void setId(int id) {
      this.id = id;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getInfo() {
      return info;
    }

    public void setInfo(String info) {
      this.info = info;
    }

  } // class CrlInfo

  private int version;

  private int countCerts;

  private String certhashAlgo;

  private List<Issuer> issuers;

  private List<CrlInfo> crlInfos;

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public int getCountCerts() {
    return countCerts;
  }

  public void setCountCerts(int countCerts) {
    this.countCerts = countCerts;
  }

  public String getCerthashAlgo() {
    return certhashAlgo;
  }

  public void setCerthashAlgo(String certhashAlgo) {
    this.certhashAlgo = certhashAlgo;
  }

  public List<Issuer> getIssuers() {
    if (issuers == null) {
      issuers = new LinkedList<>();
    }
    return issuers;
  }

  public void setIssuers(List<Issuer> issuers) {
    this.issuers = issuers;
  }

  public List<CrlInfo> getCrlInfos() {
    return crlInfos;
  }

  public void setCrlInfos(List<CrlInfo> crlInfos) {
    this.crlInfos = crlInfos;
  }

  @Override
  public void validate() throws InvalidConfException {
    notBlank(certhashAlgo, "certhashAlgo");
    validate(issuers, crlInfos);
  }

}
