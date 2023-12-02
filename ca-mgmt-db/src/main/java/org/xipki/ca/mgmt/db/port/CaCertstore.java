// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * CA CertStore configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class CaCertstore extends ValidableConf {

  public static class Cert extends IdentifiedDbObject {

    private String file;

    private String privateKeyFile;

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

    /**
     * base64 encoded transaction id.
     */
    private String tid;

    /**
     * first 8 bytes of the SHA1 sum of the requested subject.
     */
    private Long fpRs;

    private Integer crlScope;

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

    public Boolean getEe() {
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

    public String getPrivateKeyFile() {
      return privateKeyFile;
    }

    public void setPrivateKeyFile(String privateKeyFile) {
      this.privateKeyFile = privateKeyFile;
    }

    public Integer getCrlScope() {
      return crlScope;
    }

    public void setCrlScope(Integer crlScope) {
      this.crlScope = crlScope;
    }

    @Override
    public void validate() throws InvalidConfException {
      super.validate();

      notNull(caId, "caId");
      notNull(ee, "ee");
      notBlank(file, "file");
      notNull(pid, "pid");
      notNull(rev, "rev");
      notNull(rid, "rid");
      notBlank(sn, "sn");
      notNull(update, "update");
      notNull(crlScope, "crlScope");
      if (rev == 1) {
        notNull(rr, "rr");
        notNull(rt, "rt");
      }
    }

  } // method Cert

  public static class Certs extends ValidableConf {

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

  } // class Certs

  public static class Crl extends IdentifiedDbObject {

    private Integer caId;

    private String crlNo;

    private String file;

    private Integer crlScope;

    public Integer getCaId() {
      return caId;
    }

    public void setCaId(Integer caId) {
      this.caId = caId;
    }

    public String getCrlNo() {
      return crlNo;
    }

    public void setCrlNo(String crlNo) {
      this.crlNo = crlNo;
    }

    public Integer getCrlScope() {
      return crlScope;
    }

    public void setCrlScope(Integer crlScope) {
      this.crlScope = crlScope;
    }

    public String getFile() {
      return file;
    }

    public void setFile(String file) {
      this.file = file;
    }

    @Override
    public void validate() throws InvalidConfException {
      super.validate();
      notNull(caId, "caId");
      notBlank(crlNo, "crlNo");
      notBlank(file, "file");
      notNull(crlScope, "crlScope");
    }

  } // class CaHasEntry

  public static class Crls extends ValidableConf {

    private List<Crl> crls;

    public List<Crl> getCrls() {
      return crls;
    }

    public void setCrls(List<Crl> crls) {
      this.crls = crls;
    }

    public void add(Crl crl) {
      if (crls == null) {
        crls = new LinkedList<>();
      }
      crls.add(crl);
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(crls);
    }

  } // class Crls

  public static class IdName extends ValidableConf {
    private int id;
    private String name;

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

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
    }
  }

  public static class Ca extends IdName {

    private String revInfo;

    private byte[] cert;

    public byte[] getCert() {
      return cert;
    }

    public void setCert(byte[] cert) {
      this.cert = cert;
    }

    public String getRevInfo() {
      return revInfo;
    }

    public void setRevInfo(String revInfo) {
      this.revInfo = revInfo;
    }

    @Override
    public void validate() throws InvalidConfException {
      super.validate();
      notNull(cert, "cert");
    }

  }

  private int version;

  private int countCrls;

  private int countCerts;

  private List<Ca> cas;

  private List<IdName> requestors;

  private List<IdName> profiles;

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public int getCountCrls() {
    return countCrls;
  }

  public void setCountCrls(int countCrls) {
    this.countCrls = countCrls;
  }

  public int getCountCerts() {
    return countCerts;
  }

  public void setCountCerts(int countCerts) {
    this.countCerts = countCerts;
  }

  public List<Ca> getCas() {
    return cas;
  }

  public void setCas(List<Ca> cas) {
    this.cas = cas;
  }

  public List<IdName> getRequestors() {
    return requestors;
  }

  public void setRequestors(List<IdName> requestors) {
    this.requestors = requestors;
  }

  public List<IdName> getProfiles() {
    return profiles;
  }

  public void setProfiles(List<IdName> profiles) {
    this.profiles = profiles;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

}
