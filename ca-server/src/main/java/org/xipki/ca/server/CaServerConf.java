/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.xipki.util.Args;
import org.xipki.util.InvalidConfException;
import org.xipki.util.StringUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.http.SslContextConf;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;

/**
 * TODO.
 * @author Lijun Liao
 */
public class CaServerConf extends ValidatableConf {

  public static class SslContext extends ValidatableConf {

    private String name;

    private Keystore truststore;

    private String hostverifier;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public Keystore getTruststore() {
      return truststore;
    }

    public void setTruststore(Keystore truststore) {
      this.truststore = truststore;
    }

    public String getHostverifier() {
      return hostverifier;
    }

    public void setHostverifier(String hostverifier) {
      this.hostverifier = hostverifier;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
    }

  }

  public static class Keystore extends ValidatableConf {

    private String type;

    private String file;

    private String password;

    public String getType() {
      return type;
    }

    public void setType(String value) {
      this.type = value;
    }

    public String getFile() {
      return file;
    }

    public void setFile(String file) {
      this.file = file;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(String value) {
      this.password = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(type, "type");
      notEmpty(file, "file");
    }

  }

  public static class Datasource extends ValidatableConf {

    private String confFile;

    private String name;

    public String getConfFile() {
      return confFile;
    }

    public void setConfFile(String confFile) {
      this.confFile = confFile;
    }

    public String getName() {
      return name;
    }

    public void setName(String value) {
      this.name = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
      notEmpty(confFile, "confFile");
    }

  }

  /**
   * master or slave, the default is master
   */
  private boolean master = true;

  /**
   * shard id, between 0 and 127. CA systems using same database must have
   * different shard ids.
   */
  private int shardId = 0;

  private List<Datasource> datasources;

  private List<SslContext> sslContexts;

  @JSONField(serialize = false, deserialize = false)
  private Map<String, SslContextConf> sslContextConfMap = new HashMap<>();

  public static CaServerConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      CaServerConf conf;

      if (fileName.endsWith(".properties")) {
        conf = new CaServerConf();
        Properties props = new Properties();
        props.load(is);
        String caModeStr = props.getProperty("ca.mode");

        boolean masterMode;
        if (caModeStr != null) {
          if ("slave".equalsIgnoreCase(caModeStr)) {
            masterMode = false;
          } else if ("master".equalsIgnoreCase(caModeStr)) {
            masterMode = true;
          } else {
            throw new InvalidConfException("invalid ca.mode '" + caModeStr + "'");
          }
        } else {
          masterMode = true;
        }
        conf.setMaster(masterMode);

        String shardIdStr = props.getProperty("ca.shardId");
        if (StringUtil.isBlank(shardIdStr)) {
          throw new InvalidConfException("ca.shardId is not set");
        }

        int shardId;
        try {
          shardId = Integer.parseInt(shardIdStr);
        } catch (NumberFormatException ex) {
          throw new InvalidConfException("invalid ca.shardId '" + shardIdStr + "'");
        }
        conf.setShardId(shardId);

        List<Datasource> datasources = new LinkedList<>();
        conf.setDatasources(datasources);

        for (Object objKey : props.keySet()) {
          String key = (String) objKey;
          if (!StringUtil.startsWithIgnoreCase(key, "datasource.")) {
            continue;
          }

          String datasourceName = key.substring("datasource.".length());
          String datasourceFile = props.getProperty(key);

          Datasource ds = new Datasource();
          ds.setName(datasourceName);
          ds.setConfFile(datasourceFile);
          datasources.add(ds);
        }
      } else {
        conf = JSON.parseObject(Files.newInputStream(Paths.get(fileName)), CaServerConf.class);
      }

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

  public int getShardId() {
    return shardId;
  }

  public void setShardId(int shardId) {
    this.shardId = shardId;
  }

  public List<Datasource> getDatasources() {
    return datasources;
  }

  public void setDatasources(List<Datasource> datasources) {
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

  public synchronized SslContextConf getSslContextConf(String name) {
    if (sslContexts.isEmpty()) {
      return null;
    }

    if (sslContextConfMap.isEmpty()) {
      for (SslContext m : sslContexts) {
        SslContextConf conf = new SslContextConf();
        conf.setSslHostnameVerifier(m.getHostverifier());

        Keystore truststore = m.getTruststore();
        conf.setSslTruststore(truststore.getFile());
        conf.setSslTruststorePassword(truststore.getPassword());
        conf.setSslStoreType(truststore.getType());

        sslContextConfMap.put(m.getName(), conf);
      }
    }
    return sslContextConfMap.get(name);
  }

  @Override
  public void validate() throws InvalidConfException {
    if (shardId < 0 || shardId > 127) {
      throw new InvalidConfException("shardId is not in [0, 127]");
    }

    notEmpty(datasources, "datasources");
  }

}
