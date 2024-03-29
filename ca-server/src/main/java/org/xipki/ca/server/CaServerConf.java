// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.audit.Audits.AuditConf;
import org.xipki.ca.api.mgmt.CaJson;
import org.xipki.datasource.DataSourceConf;
import org.xipki.security.Securities.SecurityConf;
import org.xipki.security.util.TlsHelper;
import org.xipki.util.Args;
import org.xipki.util.FileOrBinary;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.SslContextConf;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CA server configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class CaServerConf extends ValidableConf {

  public static class SslContext extends ValidableConf {

    private String name;

    private FileOrBinary[] trustanchors;

    private String hostverifier;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public FileOrBinary[] getTrustanchors() {
      return trustanchors;
    }

    public void setTrustanchors(FileOrBinary[] trustanchors) {
      this.trustanchors = trustanchors;
    }

    public String getHostverifier() {
      return hostverifier;
    }

    public void setHostverifier(String hostverifier) {
      this.hostverifier = hostverifier;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
    }

  } // class SslContext

  public static class RemoteMgmt extends ValidableConf {

    private boolean enabled;

    private List<FileOrBinary> certs;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public List<FileOrBinary> getCerts() {
      return certs;
    }

    public void setCerts(List<FileOrBinary> certs) {
      this.certs = certs;
    }

    @Override
    public void validate() {
    }

  } // class RemoteMgmt

  public static class CtLogConf {

    private String keydir;

    public String getKeydir() {
      return keydir;
    }

    public void setKeydir(String keydir) {
      this.keydir = keydir;
    }

  } // class CtLogConf

  private AuditConf audit;

  private SecurityConf security;

  private RemoteMgmt remoteMgmt;

  /**
   * master or slave, the default is master.
   */
  private boolean master = true;

  /**
   * If set to true, two different CA instances in master mode may modify
   * CA system or generate CRL at the same time.
   */
  private boolean noLock = false;

  /**
   * If set to true, the CA operates
   */
  private boolean noRA = false;

  /**
   * shard id, between 0 and 127. CA systems using same database must have
   * different shard ids.
   */
  private int shardId = 0;

  private boolean logReqResp;

  private String reverseProxyMode;

  private List<DataSourceConf> datasources;

  private List<SslContext> sslContexts;

  private CtLogConf ctLog;

  /**
   * list of classes that implement org.xipki.ca.api.profile.CertprofileFactory
   */
  private List<String> certprofileFactories;

  /**
   * list of classes that implement org.xipki.ca.api.kpgen.KeypairGeneratorFactory
   */
  private List<String> keypairGeneratorFactories;

  private List<String> caConfFiles;

  private final Map<String, SslContextConf> sslContextConfMap = new HashMap<>();

  public static CaServerConf readConfFromFile(String fileName) throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    CaServerConf conf = CaJson.parseObject(new File(fileName), CaServerConf.class);
    conf.validate();
    return conf;
  }

  public boolean isMaster() {
    return master;
  }

  public void setMaster(boolean master) {
    this.master = master;
  }

  public boolean isNoLock() {
    return noLock;
  }

  public void setNoLock(boolean noLock) {
    this.noLock = noLock;
  }

  public boolean isNoRA() {
    return noRA;
  }

  public void setNoRA(boolean noRA) {
    this.noRA = noRA;
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public String getReverseProxyMode() {
    return reverseProxyMode;
  }

  public void setReverseProxyMode(String reverseProxyMode) {
    this.reverseProxyMode = reverseProxyMode;
  }

  public int getShardId() {
    return shardId;
  }

  public void setShardId(int shardId) {
    this.shardId = shardId;
  }

  public List<String> getCaConfFiles() {
    return caConfFiles;
  }

  public void setCaConfFiles(List<String> caConfFiles) {
    this.caConfFiles = caConfFiles;
  }

  public List<DataSourceConf> getDatasources() {
    return datasources;
  }

  public void setDatasources(List<DataSourceConf> datasources) {
    this.datasources = datasources;
  }

  public List<SslContext> getSslContexts() {
    return sslContexts;
  }

  public void setSslContexts(List<SslContext> sslContexts) {
    this.sslContexts = sslContexts;
  }

  public SslContext getSslContext(String name) {
    if (sslContexts == null) {
      return null;
    }

    for (SslContext m : sslContexts) {
      if (m.getName().equals(name)) {
        return m;
      }
    }

    return null;
  }

  public AuditConf getAudit() {
    return audit == null ? AuditConf.DEFAULT : audit;
  }

  public void setAudit(AuditConf audit) {
    this.audit = audit;
  }

  public SecurityConf getSecurity() {
    return security == null ? SecurityConf.DEFAULT : security;
  }

  public void setSecurity(SecurityConf security) {
    this.security = security;
  }

  public RemoteMgmt getRemoteMgmt() {
    return remoteMgmt;
  }

  public void setRemoteMgmt(RemoteMgmt remoteMgmt) {
    this.remoteMgmt = remoteMgmt;
  }

  public List<String> getCertprofileFactories() {
    return certprofileFactories;
  }

  public void setCertprofileFactories(List<String> certprofileFactories) {
    this.certprofileFactories = certprofileFactories;
  }

  public List<String> getKeypairGeneratorFactories() {
    return keypairGeneratorFactories;
  }

  public void setKeypairGeneratorFactories(List<String> keypairGeneratorFactories) {
    this.keypairGeneratorFactories = keypairGeneratorFactories;
  }

  public CtLogConf getCtLog() {
    return ctLog;
  }

  public void setCtLog(CtLogConf ctLog) {
    this.ctLog = ctLog;
  }

  public void initSsl() {
    if (sslContexts == null || sslContexts.isEmpty()) {
      return;
    }

    if (sslContextConfMap.isEmpty()) {
      for (SslContext m : sslContexts) {
        SslContextConf conf = new SslContextConf(m.trustanchors, m.getHostverifier());
        try {
          conf.init();
        } catch (ObjectCreationException e) {
          throw new RuntimeException(e);
        }
        sslContextConfMap.put(m.getName(), conf);
      }
    }
  }

  public SslContextConf getSslContextConf(String name) {
    return sslContextConfMap.get(name);
  }

  @Override
  public void validate() throws InvalidConfException {
    if (shardId < 0 || shardId > 127) {
      throw new InvalidConfException("shardId is not in [0, 127]");
    }

    boolean withCaconfDb = false;
    for (DataSourceConf dsConf : datasources) {
      if ("caconf".equals(dsConf.getName())) {
        withCaconfDb = true;
        break;
      }
    }

    if (caConfFiles == null) {
      if (!withCaconfDb) {
        throw new InvalidConfException("datasource 'caconf' is required but is not configured.");
      }
    } else {
      if (withCaconfDb) {
        throw new InvalidConfException("datasource 'caconf' is not allowed but is configured.");
      }
    }
    validate(remoteMgmt, security);
    TlsHelper.checkReverseProxyMode(reverseProxyMode);
  }

}
