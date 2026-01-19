// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.security.Securities.SecurityConf;
import org.xipki.security.util.TlsHelper;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataSourceConf;
import org.xipki.util.extra.audit.Audits.AuditConf;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.http.SslContextConf;
import org.xipki.util.io.FileOrBinary;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CA server configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class CaServerConf {

  public static class SslContext {

    private final String name;

    private final FileOrBinary[] trustanchors;

    private final String hostverifier;

    public SslContext(String name, String hostverifier,
                      FileOrBinary[] trustanchors) {
      this.name = Args.notBlank(name, "name");
      this.trustanchors = trustanchors;
      this.hostverifier = hostverifier;
    }

    public static SslContext parse(JsonMap json) throws CodecException {
      String name = json.getNnString("name");
      String hostverifier = json.getString("hostverifier");
      FileOrBinary[] trustanchors = FileOrBinary.parseArray(
          json.getList("trustanchors"));
      return new SslContext(name, hostverifier, trustanchors);
    }

  } // class SslContext

  public static class RemoteMgmt {

    private final boolean enabled;

    private final List<FileOrBinary> certs;

    public RemoteMgmt(boolean enabled, List<FileOrBinary> certs) {
      this.enabled = enabled;
      this.certs = certs;
    }

    public boolean isEnabled() {
      return enabled;
    }

    public List<FileOrBinary> getCerts() {
      return certs;
    }

    public static RemoteMgmt parse(JsonMap json) throws CodecException {
      boolean enabled = json.getBool("enabled", false);
      List<FileOrBinary> certs = FileOrBinary.parseList(json.getList("certs"));
      return new RemoteMgmt(enabled, certs);
    }

  } // class RemoteMgmt

  public static class CtLogConf {

    private final String keydir;

    public CtLogConf(String keydir) {
      this.keydir = Args.notBlank(keydir, "keydir");
    }

    public String getKeydir() {
      return keydir;
    }

    public static CtLogConf parse(JsonMap json) throws CodecException {
      return new CtLogConf(json.getNnString("keydir"));
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
   * list of classes that implement
   * org.xipki.ca.api.kpgen.KeypairGeneratorFactory
   */
  private List<String> keypairGeneratorFactories;

  private List<String> caConfFiles;

  private final Map<String, SslContextConf> sslContextConfMap = new HashMap<>();

  public static CaServerConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try {
      return parse(JsonParser.parseMap(Paths.get(fileName), true));
    } catch (CodecException e) {
      throw new InvalidConfException(
          "error parsing configuration " + fileName, e);
    }
  }

  public static CaServerConf parse(JsonMap json)
      throws CodecException, InvalidConfException {
    JsonMap map = json.getMap("audit");
    CaServerConf ret = new CaServerConf();
    if (map != null) {
      ret.audit = AuditConf.parse(map);
    }

    map = json.getMap("security");
    if (map != null) {
      ret.security = SecurityConf.parse(map);
    }

    map = json.getMap("remoteMgmt");
    if (map != null) {
      ret.remoteMgmt = RemoteMgmt.parse(map);
    }

    Boolean b = json.getBool("master");
    if (b != null) {
      ret.master = b;
    }

    b = json.getBool("noLock");
    if (b != null) {
      ret.noLock = b;
    }

    b = json.getBool("noRA");
    if (b != null) {
      ret.noRA = b;
    }

    Integer i = json.getInt("shardId");
    if (i != null) {
      ret.shardId = i;
    }

    b = json.getBool("logReqResp");
    if (b != null) {
      ret.logReqResp = b;
    }

    ret.reverseProxyMode = json.getString("reverseProxyMode");
    ret.datasources = DataSourceConf.parseList(json.getList("datasources"));

    JsonList list = json.getList("sslContexts");
    if (list != null) {
      ret.sslContexts = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        ret.sslContexts.add(SslContext.parse(v));
      }
    }

    map = json.getMap("ctLog");
    if (map != null) {
      ret.ctLog = CtLogConf.parse(map);
    }

    ret.certprofileFactories = json.getStringList("certprofileFactories");
    ret.keypairGeneratorFactories = json.getStringList(
        "keypairGeneratorFactories");
    ret.caConfFiles = json.getStringList("caConfFiles");

    ret.validate();
    return ret;
  }

  public boolean isMaster() {
    return master;
  }

  public boolean isNoLock() {
    return noLock;
  }

  public boolean isNoRA() {
    return noRA;
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public String getReverseProxyMode() {
    return reverseProxyMode;
  }

  public int getShardId() {
    return shardId;
  }

  public List<String> getCaConfFiles() {
    return caConfFiles;
  }

  public List<DataSourceConf> getDatasources() {
    return datasources;
  }

  public AuditConf getAudit() {
    return audit == null ? AuditConf.DEFAULT : audit;
  }

  public SecurityConf getSecurity() {
    return security == null ? SecurityConf.DEFAULT : security;
  }

  public RemoteMgmt getRemoteMgmt() {
    return remoteMgmt;
  }

  public List<String> getCertprofileFactories() {
    return certprofileFactories;
  }

  public List<String> getKeypairGeneratorFactories() {
    return keypairGeneratorFactories;
  }

  public CtLogConf getCtLog() {
    return ctLog;
  }

  public void initSsl() {
    if (sslContexts == null || sslContexts.isEmpty()) {
      return;
    }

    if (sslContextConfMap.isEmpty()) {
      for (SslContext m : sslContexts) {
        SslContextConf conf = new SslContextConf(m.trustanchors,
            m.hostverifier);
        try {
          conf.init();
        } catch (ObjectCreationException e) {
          throw new RuntimeException(e);
        }
        sslContextConfMap.put(m.name, conf);
      }
    }
  }

  public SslContextConf getSslContextConf(String name) {
    return sslContextConfMap.get(name);
  }

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
        throw new InvalidConfException(
            "datasource 'caconf' is required but is not configured.");
      }
    } else {
      if (withCaconfDb) {
        throw new InvalidConfException(
            "datasource 'caconf' is not allowed but is configured.");
      }
    }
    TlsHelper.checkReverseProxyMode(reverseProxyMode);
  }

}
