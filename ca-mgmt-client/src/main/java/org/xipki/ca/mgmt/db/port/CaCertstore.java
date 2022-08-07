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

import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * CA CertStore configuration.
 *
 * @author Lijun Liao
 */

public class CaCertstore extends ValidatableConf {

  public static class Ca extends ValidatableConf {

    private int id;

    private String name;

    private long nextCrlNo;

    private String status;

    private FileOrBinary cert;

    private FileOrValue certchain;

    private String signerType;

    private FileOrValue signerConf;

    private String revInfo;

    private String crlSignerName;

    private FileOrValue confColumn;

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

    public long getNextCrlNo() {
      return nextCrlNo;
    }

    public void setNextCrlNo(long nextCrlNo) {
      this.nextCrlNo = nextCrlNo;
    }

    public String getStatus() {
      return status;
    }

    public void setStatus(String status) {
      this.status = status;
    }

    public FileOrBinary getCert() {
      return cert;
    }

    public void setCert(FileOrBinary cert) {
      this.cert = cert;
    }

    public FileOrValue getCertchain() {
      return certchain;
    }

    public void setCertchain(FileOrValue certchain) {
      this.certchain = certchain;
    }

    public String getSignerType() {
      return signerType;
    }

    public void setSignerType(String signerType) {
      this.signerType = signerType;
    }

    public FileOrValue getSignerConf() {
      return signerConf;
    }

    public void setSignerConf(FileOrValue signerConf) {
      this.signerConf = signerConf;
    }

    public String getRevInfo() {
      return revInfo;
    }

    public void setRevInfo(String revInfo) {
      this.revInfo = revInfo;
    }

    public String getCrlSignerName() {
      return crlSignerName;
    }

    public void setCrlSignerName(String crlSignerName) {
      this.crlSignerName = crlSignerName;
    }

    public FileOrValue getConfColumn() {
      return confColumn;
    }

    public void setConfColumn(FileOrValue confColumn) {
      this.confColumn = confColumn;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(name, "name");
      notBlank(status, "status");

      notNull(cert, "cert");
      cert.validate();

      notBlank(signerType, "signerType");

      notNull(signerConf, "signerConf");
      signerConf.validate();
    }

  } // class Ca

  public static class Caalias extends ValidatableConf {

    private int caId;

    private String name;

    public int getCaId() {
      return caId;
    }

    public void setCaId(int caId) {
      this.caId = caId;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(name, "name");
    }

  } // class Caalias

  public static class Caconf extends ValidatableConf {

    private int version;

    private List<DbSchemaEntry> dbSchemas;

    private List<Signer> signers;

    private List<NameTypeConf> keypairGens;

    private List<IdNameTypeConf> requestors;

    private List<IdNameTypeConf> publishers;

    private List<IdNameTypeConf> profiles;

    private List<Ca> cas;

    private List<Caalias> caaliases;

    private List<CaHasRequestor> caHasRequestors;

    private List<CaHasPublisher> caHasPublishers;

    private List<CaHasProfile> caHasProfiles;

    public int getVersion() {
      return version;
    }

    public void setVersion(int version) {
      this.version = version;
    }

    public List<DbSchemaEntry> getDbSchemas() {
      if (dbSchemas == null) {
        dbSchemas = new LinkedList<>();
      }
      return dbSchemas;
    }

    public void setDbSchemas(List<DbSchemaEntry> dbSchemas) {
      this.dbSchemas = dbSchemas;
    }

    public List<Signer> getSigners() {
      if (signers == null) {
        signers = new LinkedList<>();
      }
      return signers;
    }

    public void setSigners(List<Signer> signers) {
      this.signers = signers;
    }

    public List<IdNameTypeConf> getRequestors() {
      if (requestors == null) {
        requestors = new LinkedList<>();
      }
      return requestors;
    }

    public void setRequestors(List<IdNameTypeConf> requestors) {
      this.requestors = requestors;
    }

    public List<IdNameTypeConf> getPublishers() {
      if (publishers == null) {
        publishers = new LinkedList<>();
      }
      return publishers;
    }

    public void setPublishers(List<IdNameTypeConf> publishers) {
      this.publishers = publishers;
    }

    public List<IdNameTypeConf> getProfiles() {
      if (profiles == null) {
        profiles = new LinkedList<>();
      }
      return profiles;
    }

    public void setProfiles(List<IdNameTypeConf> profiles) {
      this.profiles = profiles;
    }

    public List<Ca> getCas() {
      if (cas == null) {
        cas = new LinkedList<>();
      }
      return cas;
    }

    public void setCas(List<Ca> cas) {
      this.cas = cas;
    }

    public List<Caalias> getCaaliases() {
      if (caaliases == null) {
        caaliases = new LinkedList<>();
      }
      return caaliases;
    }

    public void setCaaliases(List<Caalias> caaliases) {
      this.caaliases = caaliases;
    }

    public List<CaHasRequestor> getCaHasRequestors() {
      if (caHasRequestors == null) {
        caHasRequestors = new LinkedList<>();
      }
      return caHasRequestors;
    }

    public void setCaHasRequestors(List<CaHasRequestor> caHasRequestors) {
      this.caHasRequestors = caHasRequestors;
    }

    public List<CaHasPublisher> getCaHasPublishers() {
      if (caHasPublishers == null) {
        caHasPublishers = new LinkedList<>();
      }
      return caHasPublishers;
    }

    public void setCaHasPublishers(List<CaHasPublisher> caHasPublishers) {
      this.caHasPublishers = caHasPublishers;
    }

    public List<CaHasProfile> getCaHasProfiles() {
      if (caHasProfiles == null) {
        caHasProfiles = new LinkedList<>();
      }
      return caHasProfiles;
    }

    public void setCaHasProfiles(List<CaHasProfile> caHasProfiles) {
      this.caHasProfiles = caHasProfiles;
    }

    public List<NameTypeConf> getKeypairGens() {
      return keypairGens;
    }

    public void setKeypairGens(List<NameTypeConf> keypairGens) {
      this.keypairGens = keypairGens;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      validate(signers);
      validate(requestors);
      validate(publishers);
      validate(profiles);
      validate(cas);
      validate(caaliases);
      validate(caHasRequestors);
      validate(caHasPublishers);
      validate(caHasProfiles);
      validate(keypairGens);
    }

  } // class Caconf

  public abstract static class CaHasEntry extends ValidatableConf {

    private int caId;

    public int getCaId() {
      return caId;
    }

    public void setCaId(int caId) {
      this.caId = caId;
    }

  } // class CaHasEntry

  public static class CaHasPublisher extends CaHasEntry {

    private int publisherId;

    public int getPublisherId() {
      return publisherId;
    }

    public void setPublisherId(int publisherId) {
      this.publisherId = publisherId;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }

  } // class CaHasPublisher

  public static class CaHasProfile extends CaHasEntry {

    private int profileId;

    public int getProfileId() {
      return profileId;
    }

    public void setProfileId(int profileId) {
      this.profileId = profileId;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }

  } // class CaHasProfile

  public static class CaHasRequestor extends CaHasEntry {

    private int requestorId;

    private int permission;

    private String profiles;

    public int getRequestorId() {
      return requestorId;
    }

    public void setRequestorId(int requestorId) {
      this.requestorId = requestorId;
    }

    public int getPermission() {
      return permission;
    }

    public void setPermission(int permission) {
      this.permission = permission;
    }

    public String getProfiles() {
      return profiles;
    }

    public void setProfiles(String profiles) {
      this.profiles = profiles;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }

  } // class CaHasRequestor

  public static class CaHasUser extends CaHasEntry {

    private int id;

    private int userId;

    private int active;

    private int permission;

    private String profiles;

    public int getId() {
      return id;
    }

    public void setId(int id) {
      this.id = id;
    }

    public int getUserId() {
      return userId;
    }

    public void setUserId(int userId) {
      this.userId = userId;
    }

    public int getActive() {
      return active;
    }

    public void setActive(int active) {
      this.active = active;
    }

    public int getPermission() {
      return permission;
    }

    public void setPermission(int permission) {
      this.permission = permission;
    }

    public String getProfiles() {
      return profiles;
    }

    public void setProfiles(String profiles) {
      this.profiles = profiles;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }

  } // class CaHasUser

  public static class Cert extends IdentifidDbObject {

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
    public void validate()
        throws InvalidConfException {
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
    public void validate()
        throws InvalidConfException {
      validate(certs);
    }

  } // class Certs

  public static class Crl extends IdentifidDbObject {

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
    public void validate()
        throws InvalidConfException {
      super.validate();
      notNull(caId, "caId");
      notBlank(crlNo, "crlNo");
      notBlank(file, "file");
      notNull(crlScope, "crlScope");
    }

  } // class CaHasEntry

  public static class Crls extends ValidatableConf {

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
    public void validate()
        throws InvalidConfException {
      validate(crls);
    }

  } // class Crls

  public static class DbSchemaEntry extends ValidatableConf {

    private String name;
    private String value;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getValue() {
      return value;
    }

    public void setValue(String value) {
      this.value = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notNull(value, "value");
    }
  }

  public static class DeltaCrlCacheEntry extends ValidatableConf {

    private String serial;

    private int caId;

    public String getSerial() {
      return serial;
    }

    public void setSerial(String serial) {
      this.serial = serial;
    }

    public int getCaId() {
      return caId;
    }

    public void setCaId(int caId) {
      this.caId = caId;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(serial, "serial");
    }

  } // class DeltaCrlCacheEntry

  public static class NameTypeConf extends ValidatableConf {

    private String name;

    private String type;

    private FileOrValue conf;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getType() {
      return type;
    }

    public void setType(String type) {
      this.type = type;
    }

    public FileOrValue getConf() {
      return conf;
    }

    public void setConf(FileOrValue conf) {
      this.conf = conf;
    }

    @Override
    public void validate()
            throws InvalidConfException {
      notBlank(name, "name");
      notBlank(type, "type");
      if (conf != null) {
        conf.validate();
      }
    }

  } // class IdNameTypeConf

  public static class IdNameTypeConf extends NameTypeConf {

    private int id;

    public int getId() {
      return id;
    }

    public void setId(int id) {
      this.id = id;
    }

  } // class IdNameTypeConf

  public static class ReqCert extends IdentifidDbObject {

    private Long rid;

    private Long cid;

    public Long getRid() {
      return rid;
    }

    public void setRid(long rid) {
      this.rid = rid;
    }

    public Long getCid() {
      return cid;
    }

    public void setCid(long cid) {
      this.cid = cid;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      super.validate();
      notNull(rid, "rid");
      notNull(cid, "cid");
    }

  } // class ReqCert

  public static class ReqCerts extends ValidatableConf {

    private List<ReqCert> reqCerts;

    public List<ReqCert> getReqCerts() {
      if (reqCerts == null) {
        reqCerts = new LinkedList<>();
      }
      return reqCerts;
    }

    public void setReqCerts(List<ReqCert> reqCerts) {
      this.reqCerts = reqCerts;
    }

    public void add(ReqCert reqCert) {
      if (reqCerts == null) {
        reqCerts = new LinkedList<>();
      }
      reqCerts.add(reqCert);
    }

    @Override
    public void validate()
        throws InvalidConfException {
      validate(reqCerts);
    }

  } // class ReqCerts

  public static class Request extends IdentifidDbObject {

    private Long update;

    private String file;

    public Long getUpdate() {
      return update;
    }

    public void setUpdate(Long update) {
      this.update = update;
    }

    public String getFile() {
      return file;
    }

    public void setFile(String file) {
      this.file = file;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      super.validate();
      notNull(update, "update");
      notBlank(file, "file");
    }

  } // class Request

  public static class Requests extends ValidatableConf {

    private List<Request> requests;

    public List<Request> getRequests() {
      if (requests == null) {
        requests = new LinkedList<>();
      }
      return requests;
    }

    public void setRequests(List<Request> requests) {
      this.requests = requests;
    }

    public void add(Request request) {
      if (requests == null) {
        requests = new LinkedList<>();
      }
      requests.add(request);
    }

    @Override
    public void validate()
        throws InvalidConfException {
      validate(requests);
    }

  } // class Requests

  public static class Signer extends ValidatableConf {

    private String name;

    private String type;

    private FileOrValue conf;

    private FileOrBinary cert;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getType() {
      return type;
    }

    public void setType(String type) {
      this.type = type;
    }

    public FileOrValue getConf() {
      return conf;
    }

    public void setConf(FileOrValue conf) {
      this.conf = conf;
    }

    public FileOrBinary getCert() {
      return cert;
    }

    public void setCert(FileOrBinary cert) {
      this.cert = cert;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notBlank(name, "name");
      notBlank(type, "type");
      notNull(conf, "conf");
      conf.validate();
      validate(cert);
    }

  } // class Signer

  public static class ToPublish extends ValidatableConf {

    private int pubId;

    private long certId;

    private int caId;

    public int getPubId() {
      return pubId;
    }

    public void setPubId(int pubId) {
      this.pubId = pubId;
    }

    public long getCertId() {
      return certId;
    }

    public void setCertId(long certId) {
      this.certId = certId;
    }

    public int getCaId() {
      return caId;
    }

    public void setCaId(int caId) {
      this.caId = caId;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }

  } // class ToPublish

  private int version;

  private int countCrls;

  private int countCerts;

  private int countRequests;

  private int countReqCerts;

  private List<ToPublish> publishQueue;

  private List<DeltaCrlCacheEntry> deltaCrlCache;

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

  public int getCountRequests() {
    return countRequests;
  }

  public void setCountRequests(int countRequests) {
    this.countRequests = countRequests;
  }

  public int getCountReqCerts() {
    return countReqCerts;
  }

  public void setCountReqCerts(int countReqCerts) {
    this.countReqCerts = countReqCerts;
  }

  public List<ToPublish> getPublishQueue() {
    if (publishQueue == null) {
      publishQueue = new LinkedList<>();
    }
    return publishQueue;
  }

  public void setPublishQueue(List<ToPublish> publishQueue) {
    this.publishQueue = publishQueue;
  }

  public List<DeltaCrlCacheEntry> getDeltaCrlCache() {
    if (deltaCrlCache == null) {
      deltaCrlCache = new LinkedList<>();
    }
    return deltaCrlCache;
  }

  public void setDeltaCrlCache(List<DeltaCrlCacheEntry> deltaCrlCache) {
    this.deltaCrlCache = deltaCrlCache;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    validate(publishQueue);
    validate(deltaCrlCache);
  }

}
