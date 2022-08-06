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

package org.xipki.ca.server;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;
import org.xipki.audit.Audits.AuditConf;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.datasource.DataSourceConf;
import org.xipki.security.Securities.SecurityConf;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.SslContextConf;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CA server configuration.
 *
 * @author Lijun Liao
 */
public class CaServerConf extends ValidatableConf {

  public static class SslContext extends ValidatableConf {

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
    public void validate()
        throws InvalidConfException {
      notBlank(name, "name");
    }

  } // class SslContext

  public static class RemoteMgmt extends ValidatableConf {

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
    public void validate()
        throws InvalidConfException {
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
   * shard id, between 0 and 127. CA systems using same database must have
   * different shard ids.
   */
  private int shardId = 0;

  private boolean logReqResp;

  private List<DataSourceConf> datasources;

  private List<SslContext> sslContexts;

  private CtLogConf ctLog;

  /**
   * list of classes that implement org.xipki.ca.api.profile.CertprofileFactory
   */
  private List<String> certprofileFactories;

  @JSONField(serialize = false, deserialize = false)
  private Map<String, SslContextConf> sslContextConfMap = new HashMap<>();

  public static CaServerConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      CaServerConf conf = JSON.parseObject(is, CaServerConf.class);
      conf.validate();

      return conf;
    }
  }

  public boolean isMaster() {
    return master;
  }

  public void setMaster(boolean master) {
    this.master = master;
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public void setLogReqResp(boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public int getShardId() {
    return shardId;
  }

  public void setShardId(int shardId) {
    this.shardId = shardId;
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

  public CtLogConf getCtLog() {
    return ctLog;
  }

  public void setCtLog(CtLogConf ctLog) {
    this.ctLog = ctLog;
  }

  public void initSsl() throws CaMgmtException {
    if (sslContexts == null || sslContexts.isEmpty()) {
      return;
    }

    if (sslContextConfMap.isEmpty()) {
      for (SslContext m : sslContexts) {
        SslContextConf conf = new SslContextConf();
        conf.setSslHostnameVerifier(m.getHostverifier());
        conf.setSslTrustanchors(m.trustanchors);
        try {
          conf.getSslContext();
        } catch (ObjectCreationException e) {
          throw new RuntimeException(e);
        }
        sslContextConfMap.put(m.getName(), conf);
      }
    }
  }

  public SslContextConf getSslContextConf(String name) {
    return sslContextConfMap.get(name);
  } // method getSslContextConf

  @Override
  public void validate()
      throws InvalidConfException {
    if (shardId < 0 || shardId > 127) {
      throw new InvalidConfException("shardId is not in [0, 127]");
    }

    notEmpty(datasources, "datasources");
    validate(remoteMgmt);
    validate(security);
  } // method validate

}
