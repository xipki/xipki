// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * CA configuration types.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class CaConfType {

  public static class CaSystem extends ValidatableConf {

    /**
     * Specify the base directory for relative path specified in this
     * configuration file. Use 'APP_DIR' for application working directory.
     * Default is the directory where this configuration file locates. Will be
     * ignored if this configuration file is contained in a ZIP file.
     */
    private String basedir;

    /**
     * The element name specifies the property name, the element
     * value specifies the property value. The property propname can be referenced by
     * ${propname}.

     * Property baseDir is reserved which points to the parent directory
     * of the configuration file
     */
    private Map<String, String> properties;

    private Map<String, String> dbSchemas;

    private List<Signer> signers;

    private List<Requestor> requestors;

    private List<NameTypeConf> publishers;

    private List<NameTypeConf> profiles;

    private List<NameTypeConf> keypairGens;

    private List<Ca> cas;

    public String getBasedir() {
      return basedir;
    }

    public void setBasedir(String basedir) {
      this.basedir = basedir;
    }

    public Map<String, String> getProperties() {
      if (properties == null) {
        properties = new HashMap<>();
      }
      return properties;
    }

    public void setProperties(Map<String, String> properties) {
      this.properties = properties;
    }

    public Map<String, String> getDbSchemas() {
      if (dbSchemas == null) {
        dbSchemas = new HashMap<>();
      }
      return dbSchemas;
    }

    public void setDbSchemas(Map<String, String> dbSchemas) {
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

    public List<Requestor> getRequestors() {
      if (requestors == null) {
        requestors = new LinkedList<>();
      }
      return requestors;
    }

    public void setRequestors(List<Requestor> requestors) {
      this.requestors = requestors;
    }

    public List<NameTypeConf> getPublishers() {
      if (publishers == null) {
        publishers = new LinkedList<>();
      }
      return publishers;
    }

    public void setPublishers(List<NameTypeConf> publishers) {
      this.publishers = publishers;
    }

    public List<NameTypeConf> getProfiles() {
      if (profiles == null) {
        profiles = new LinkedList<>();
      }
      return profiles;
    }

    public void setProfiles(List<NameTypeConf> profiles) {
      this.profiles = profiles;
    }

    public List<NameTypeConf> getKeypairGens() {
      if (keypairGens == null) {
        keypairGens = new LinkedList<>();
      }
      return keypairGens;
    }

    public void setKeypairGens(List<NameTypeConf> keypairGens) {
      this.keypairGens = keypairGens;
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

    @Override
    public void validate() throws InvalidConfException {
      validate(signers, requestors, publishers, profiles, cas);
    } // methdo validate

  } // class CaSystem

  public static class CaHasRequestor extends ValidatableConf {

    private String requestorName;

    private List<String> permissions;

    private List<String> profiles;

    public String getRequestorName() {
      return requestorName;
    }

    public void setRequestorName(String requestorName) {
      this.requestorName = requestorName;
    }

    public List<String> getPermissions() {
      if (permissions == null) {
        permissions = new LinkedList<>();
      }
      return permissions;
    }

    public void setPermissions(List<String> permissions) {
      this.permissions = permissions;
    }

    public List<String> getProfiles() {
      if (profiles == null) {
        profiles = new LinkedList<>();
      }
      return profiles;
    }

    public void setProfiles(List<String> profiles) {
      this.profiles = profiles;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(requestorName, "requestorName");
      notEmpty(permissions, "permissions");
    }

  } // class CaHasRequestor

  public static class CaInfo extends ValidatableConf {

    /**
     * If genSelfIssued is preset, it must be absent; Otherwise it specifies the CA certificate
     */
    private FileOrBinary cert;

    /**
     * Certificate chain without the certificate specified in {@code #cert}.
     */
    private List<FileOrBinary> certchain;

    private Integer expirationPeriod;

    private Map<String, String> extraControl;

    /**
     * A new self-issued CA certificate will be generated.
     */
    private GenSelfIssued genSelfIssued;

    private Integer keepExpiredCertDays;

    private List<String> permissions;

    private String maxValidity;

    private Map<String, Object> crlControl;

    private Map<String, Object> ctlogControl;

    private Map<String, Object> revokeSuspendedControl;

    private String crlSignerName;

    private List<String> keypairGenNames;

    private boolean saveCert = true;

    private boolean saveKeyPair;

    private String signerType;

    private FileOrValue signerConf;

    private String status;

    /**
     * Valid values are strict, cutoff and lax. Default is strict
     */
    private String validityMode;

    private long nextCrlNo;

    private Integer numCrls;

    private int snSize;

    private CaUris caUris;

    public FileOrBinary getCert() {
      return cert;
    }

    public void setCert(FileOrBinary cert) {
      this.cert = cert;
    }

    public List<FileOrBinary> getCertchain() {
      return certchain;
    }

    public void setCertchain(List<FileOrBinary> certchain) {
      this.certchain = certchain;
    }

    public Integer getExpirationPeriod() {
      return expirationPeriod;
    }

    public void setExpirationPeriod(Integer expirationPeriod) {
      this.expirationPeriod = expirationPeriod;
    }

    public Map<String, String> getExtraControl() {
      return extraControl;
    }

    public void setExtraControl(Map<String, String> extraControl) {
      this.extraControl = extraControl;
    }

    public GenSelfIssued getGenSelfIssued() {
      return genSelfIssued;
    }

    public void setGenSelfIssued(GenSelfIssued genSelfIssued) {
      this.genSelfIssued = genSelfIssued;
    }

    public Integer getKeepExpiredCertDays() {
      return keepExpiredCertDays;
    }

    public void setKeepExpiredCertDays(Integer keepExpiredCertDays) {
      this.keepExpiredCertDays = keepExpiredCertDays;
    }

    public List<String> getPermissions() {
      if (permissions == null) {
        permissions = new LinkedList<>();
      }
      return permissions;
    }

    public void setPermissions(List<String> permissions) {
      this.permissions = permissions;
    }

    public String getMaxValidity() {
      return maxValidity;
    }

    public void setMaxValidity(String maxValidity) {
      this.maxValidity = maxValidity;
    }

    public Map<String, Object> getCrlControl() {
      return crlControl;
    }

    public void setCrlControl(Map<String, Object> crlControl) {
      this.crlControl = crlControl;
    }

    public Map<String, Object> getCtlogControl() {
      return ctlogControl;
    }

    public void setCtlogControl(Map<String, Object> ctlogControl) {
      this.ctlogControl = ctlogControl;
    }

    public Map<String, Object> getRevokeSuspendedControl() {
      return revokeSuspendedControl;
    }

    public void setRevokeSuspendedControl(Map<String, Object> revokeSuspendedControl) {
      this.revokeSuspendedControl = revokeSuspendedControl;
    }

    public String getCrlSignerName() {
      return crlSignerName;
    }

    public void setCrlSignerName(String crlSignerName) {
      this.crlSignerName = crlSignerName;
    }

    public List<String> getKeypairGenNames() {
      return keypairGenNames;
    }

    public void setKeypairGenNames(List<String> keypairGenNames) {
      this.keypairGenNames = keypairGenNames;
    }

    public boolean isSaveCert() {
      return saveCert;
    }

    public void setSaveCert(boolean saveCert) {
      this.saveCert = saveCert;
    }

    public boolean isSaveKeyPair() {
      return saveKeyPair;
    }

    public void setSaveKeyPair(boolean saveKeyPair) {
      this.saveKeyPair = saveKeyPair;
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

    public String getStatus() {
      return status;
    }

    public void setStatus(String status) {
      this.status = status;
    }

    public String getValidityMode() {
      return validityMode;
    }

    public void setValidityMode(String validityMode) {
      this.validityMode = validityMode;
    }

    public long getNextCrlNo() {
      return nextCrlNo;
    }

    public void setNextCrlNo(long nextCrlNo) {
      this.nextCrlNo = nextCrlNo;
    }

    public Integer getNumCrls() {
      return numCrls;
    }

    public void setNumCrls(Integer numCrls) {
      this.numCrls = numCrls;
    }

    public int getSnSize() {
      return snSize;
    }

    public void setSnSize(int snSize) {
      if (snSize > CaManager.MAX_SERIALNUMBER_SIZE) {
        this.snSize = CaManager.MAX_SERIALNUMBER_SIZE;
      } else this.snSize = Math.max(snSize, CaManager.MIN_SERIALNUMBER_SIZE);
    }

    public CaUris getCaUris() {
      return caUris;
    }

    public void setCaUris(CaUris caUris) {
      this.caUris = caUris;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (genSelfIssued != null) {
        if (cert != null) {
          throw new InvalidConfException("cert and genSelfIssued may not be both non-null");
        }
      }
      notBlank(maxValidity, "maxValidity");
      notBlank(signerType, "signerType");
      notNull(signerConf, "signerConf");
      notBlank(status, status);

      validate(genSelfIssued, cert, signerConf, caUris);
    } // method validate

  } // class CaInfo

  public static class Ca extends ValidatableConf {

    private String name;

    private CaInfo caInfo;

    private List<String> aliases;

    private List<String> profiles;

    private List<CaHasRequestor> requestors;

    private List<String> publishers;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public CaInfo getCaInfo() {
      return caInfo;
    }

    public void setCaInfo(CaInfo caInfo) {
      this.caInfo = caInfo;
    }

    public List<String> getAliases() {
      if (aliases == null) {
        aliases = new LinkedList<>();
      }
      return aliases;
    }

    public void setAliases(List<String> aliases) {
      this.aliases = aliases;
    }

    public List<String> getProfiles() {
      if (profiles == null) {
        profiles = new LinkedList<>();
      }
      return profiles;
    }

    public void setProfiles(List<String> profiles) {
      this.profiles = profiles;
    }

    public List<CaHasRequestor> getRequestors() {
      if (requestors == null) {
        requestors = new LinkedList<>();
      }
      return requestors;
    }

    public void setRequestors(List<CaHasRequestor> requestors) {
      this.requestors = requestors;
    }

    public List<String> getPublishers() {
      if (publishers == null) {
        publishers = new LinkedList<>();
      }
      return publishers;
    }

    public void setPublishers(List<String> publishers) {
      this.publishers = publishers;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      validate(caInfo);
      validate(requestors);
    }

  } // class Ca

  public static class CaUris extends ValidatableConf {

    private List<String> cacertUris;

    private List<String> crlUris;

    private List<String> deltaCrlUris;

    private List<String> ocspUris;

    public List<String> getCacertUris() {
      if (cacertUris == null) {
        cacertUris = new LinkedList<>();
      }
      return cacertUris;
    }

    public void setCacertUris(List<String> cacertUris) {
      this.cacertUris = cacertUris;
    }

    public List<String> getCrlUris() {
      if (crlUris == null) {
        crlUris = new LinkedList<>();
      }
      return crlUris;
    }

    public void setCrlUris(List<String> crlUris) {
      this.crlUris = crlUris;
    }

    public List<String> getDeltaCrlUris() {
      if (deltaCrlUris == null) {
        deltaCrlUris = new LinkedList<>();
      }
      return deltaCrlUris;
    }

    public void setDeltaCrlUris(List<String> deltaCrlUris) {
      this.deltaCrlUris = deltaCrlUris;
    }

    public List<String> getOcspUris() {
      if (ocspUris == null) {
        ocspUris = new LinkedList<>();
      }
      return ocspUris;
    }

    public void setOcspUris(List<String> ocspUris) {
      this.ocspUris = ocspUris;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class CaUris

  public static class GenSelfIssued extends ValidatableConf {

    private String subject;

    private String profile;

    private String serialNumber;

    private String notBefore;

    private String notAfter;

    public String getSubject() {
      return subject;
    }

    public void setSubject(String subject) {
      this.subject = subject;
    }

    public String getProfile() {
      return profile;
    }

    public void setProfile(String profile) {
      this.profile = profile;
    }

    public String getSerialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
      this.serialNumber = serialNumber;
    }

    public String getNotBefore() {
      return notBefore;
    }

    public void setNotBefore(String notBefore) {
      this.notBefore = notBefore;
    }

    public String getNotAfter() {
      return notAfter;
    }

    public void setNotAfter(String notAfter) {
      this.notAfter = notAfter;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(subject, "subject");
    }

  } // class GenSelfIssued

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
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notBlank(type, "type");
      validate(conf);
    }

  } // class NameTypeConf

  public static class Requestor extends ValidatableConf {

    private String name;

    private String type;

    private FileOrValue conf;

    private FileOrBinary binaryConf;

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

    public FileOrBinary getBinaryConf() {
      return binaryConf;
    }

    public void setBinaryConf(FileOrBinary binaryConf) {
      this.binaryConf = binaryConf;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notBlank(type, "type");
      exactOne(conf, "conf", binaryConf, "binaryConf");
      validate(conf, binaryConf);
    }

  } // class Requestor

  public static class Signer extends ValidatableConf {

    private String type;

    private FileOrValue conf;

    private FileOrBinary cert;

    private String name;

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

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notBlank(type, "type");
      notNull(conf, "conf");
      validate(conf, cert);
    }

  } // class Signer

}
