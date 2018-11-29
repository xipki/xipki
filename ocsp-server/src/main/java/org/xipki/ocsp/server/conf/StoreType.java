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

package org.xipki.ocsp.server.conf;

import org.xipki.util.conf.FileOrValue;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class StoreType extends ValidatableConf {

  private StoreType.Source source;

  private Boolean ignoreExpiredCert;

  private Boolean ignoreNotYetValidCert;

  private Integer retentionInterval;

  private Boolean unknownSerialAsGood;

  private Boolean includeArchiveCutoff;

  private Boolean includeCrlId;

  private String name;

  public StoreType.Source getSource() {
    return source;
  }

  public void setSource(StoreType.Source source) {
    this.source = source;
  }

  public Boolean getIgnoreExpiredCert() {
    return ignoreExpiredCert;
  }

  public void setIgnoreExpiredCert(Boolean ignoreExpiredCert) {
    this.ignoreExpiredCert = ignoreExpiredCert;
  }

  public Boolean getIgnoreNotYetValidCert() {
    return ignoreNotYetValidCert;
  }

  public void setIgnoreNotYetValidCert(Boolean ignoreNotYetValidCert) {
    this.ignoreNotYetValidCert = ignoreNotYetValidCert;
  }

  public Integer getRetentionInterval() {
    return retentionInterval;
  }

  public void setRetentionInterval(Integer retentionInterval) {
    this.retentionInterval = retentionInterval;
  }

  public Boolean getUnknownSerialAsGood() {
    return unknownSerialAsGood;
  }

  public void setUnknownSerialAsGood(Boolean unknownSerialAsGood) {
    this.unknownSerialAsGood = unknownSerialAsGood;
  }

  public Boolean getIncludeArchiveCutoff() {
    return includeArchiveCutoff;
  }

  public void setIncludeArchiveCutoff(Boolean includeArchiveCutoff) {
    this.includeArchiveCutoff = includeArchiveCutoff;
  }

  public Boolean getIncludeCrlId() {
    return includeCrlId;
  }

  public void setIncludeCrlId(Boolean includeCrlId) {
    this.includeCrlId = includeCrlId;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    notNull(source, "source");
  }

  public static class Source extends ValidatableConf {

    private String type;

    private String datasource;

    private FileOrValue conf;

    public String getType() {
      return type;
    }

    public void setType(String value) {
      this.type = value;
    }

    public String getDatasource() {
      return datasource;
    }

    public void setDatasource(String value) {
      this.datasource = value;
    }

    public FileOrValue getConf() {
      return conf;
    }

    public void setConf(FileOrValue value) {
      this.conf = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(type, "type");
    }

  }

}
