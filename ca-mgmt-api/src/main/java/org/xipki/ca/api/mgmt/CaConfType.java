// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.StringUtil;
import org.xipki.util.ValidableConf;
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

  public static class CaSystem extends ValidableConf {

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

  public static class CaHasRequestor extends ValidableConf {

    private String requestorName;

    private Permissions permissions;

    private List<String> profiles;

    public String getRequestorName() {
      return requestorName;
    }

    public void setRequestorName(String requestorName) {
      this.requestorName = StringUtil.lowercase(requestorName);
    }

    public Permissions getPermissions() {
      return permissions;
    }

    public void setPermissions(Permissions permissions) {
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
      notNull(permissions, "permissions");
    }

  } // class CaHasRequestor

  public static class CaInfo extends BaseCaInfo {

    /**
     * If genSelfIssued is preset, it must be absent; Otherwise it specifies the CA certificate
     */
    private FileOrBinary cert;

    /**
     * Certificate chain without the certificate specified in {@code #cert}.
     */
    private List<FileOrBinary> certchain;

    /**
     * A new self-issued CA certificate will be generated.
     */
    private GenSelfIssued genSelfIssued;

    private FileOrValue signerConf;

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

    public GenSelfIssued getGenSelfIssued() {
      return genSelfIssued;
    }

    public void setGenSelfIssued(GenSelfIssued genSelfIssued) {
      this.genSelfIssued = genSelfIssued;
    }

    public FileOrValue getSignerConf() {
      return signerConf;
    }

    public void setSignerConf(FileOrValue signerConf) {
      this.signerConf = signerConf;
    }

    @Override
    public void validate() throws InvalidConfException {
      super.validate();
      if (genSelfIssued != null) {
        if (cert != null) {
          throw new InvalidConfException("cert and genSelfIssued may not be both non-null");
        }
      }
      notNull(signerConf, "signerConf");
      validate(genSelfIssued, cert, signerConf);
    } // method validate

  } // class CaInfo

  public static class IdNameConf extends ValidableConf {

    private Integer id;

    private String name;

    public Integer getId() {
      return id;
    }

    public void setId(Integer id) {
      this.id = id;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = StringUtil.lowercase(name);
    }

    @Override
    public void validate() throws InvalidConfException {
      CaConfs.checkName(name, "name");
    }
  }

  public static class Ca extends IdNameConf {

    private CaInfo caInfo;

    private List<String> aliases;

    private List<String> profiles;

    private List<CaHasRequestor> requestors;

    private List<String> publishers;

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
      this.aliases = StringUtil.lowercase(aliases);
    }

    public List<String> getProfiles() {
      if (profiles == null) {
        profiles = new LinkedList<>();
      }
      return profiles;
    }

    public void setProfiles(List<String> profiles) {
      this.profiles = StringUtil.lowercase(profiles);
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
      this.publishers = StringUtil.lowercase(publishers);
    }

    @Override
    public void validate() throws InvalidConfException {
      super.validate();
      validate(caInfo);
      validate(requestors);

      if (aliases != null) {
        for (String alias : aliases) {
          CaConfs.checkName(alias, "CA alias");
        }
      }
    }

  } // class Ca

  public static class GenSelfIssued extends ValidableConf {

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

  public static class NameTypeConf extends IdNameConf {

    private String type;

    private FileOrValue conf;

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
      super.validate();
      notBlank(type, "type");
      validate(conf);
    }

  } // class NameTypeConf

  public static class Requestor extends IdNameConf {

    private String type;

    private FileOrValue conf;

    private FileOrBinary binaryConf;

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
      super.validate();
      notBlank(type, "type");
      exactOne(conf, "conf", binaryConf, "binaryConf");
      validate(conf, binaryConf);
    }

  } // class Requestor

  public static class Signer extends NameTypeConf {

    private FileOrBinary cert;

    public FileOrBinary getCert() {
      return cert;
    }

    public void setCert(FileOrBinary cert) {
      this.cert = cert;
    }

    public void validate() throws InvalidConfException {
      super.validate();
      validate(cert);
    }

  } // class Signer

}
