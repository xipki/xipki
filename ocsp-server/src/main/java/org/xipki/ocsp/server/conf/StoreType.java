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

import java.util.List;

import org.xipki.ocsp.api.OcspStore.SourceConf;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

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

    private SourceConfImpl conf;

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

    public SourceConfImpl getConf() {
      return conf;
    }

    public void setConf(SourceConfImpl value) {
      this.conf = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(type, "type");
    }

  }

  public static class SourceConfImpl extends ValidatableConf implements SourceConf {

    private DbSourceConf dbSource;

    private CrlSourceConf crlSource;

    private Object custom;

    public DbSourceConf getDbSource() {
      return dbSource;
    }

    public void setDbSource(DbSourceConf dbSource) {
      this.dbSource = dbSource;
    }

    public CrlSourceConf getCrlSource() {
      return crlSource;
    }

    public void setCrlSource(CrlSourceConf crlSource) {
      this.crlSource = crlSource;
    }

    public Object getCustom() {
      return custom;
    }

    public void setCustom(Object custom) {
      this.custom = custom;
    }

    @Override
    public void validate() throws InvalidConfException {
      int occurrences = 0;
      if (dbSource != null) {
        occurrences++;
      }

      if (crlSource == null) {
        occurrences++;
      }

      if (custom != null) {
        occurrences++;
      }

      if (occurrences > 1) {
        throw new InvalidConfException("maximal one of dbSource, crlSource and custom may be set");
      }
    }

  }

  public static class CaCerts extends ValidatableConf {

    /**
     * Files of CA certificates to be considered.<br/>
     * optional. Default is all.
     */
    private List<String> includes;

    /**
     * Comma-separated files of CA certificates to be not considered
     * optional. Default is none.
     */
    private List<String> excludes;

    public List<String> getIncludes() {
      return includes;
    }

    public void setIncludes(List<String> includes) {
      this.includes = includes;
    }

    public List<String> getExcludes() {
      return excludes;
    }

    public void setExcludes(List<String> excludes) {
      this.excludes = excludes;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  }

  public static class DbSourceConf extends ValidatableConf {

    private CaCerts caCerts;

    public CaCerts getCaCerts() {
      return caCerts;
    }

    public void setCaCerts(CaCerts caCerts) {
      this.caCerts = caCerts;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  }

  public static class CrlSourceConf extends ValidatableConf {

    /**
     * CRL file.<br/>
     * The optional file ${crlFile}.revocation contains the revocation information
     * of the CA itself.<br/>
     * Just create the file ${crlFile}.UPDATEME to tell responder to update the CRL.<br/>
     * required
     */
    private String crlFile;

    /**
     * CRL url<br/>
     * optional, default is none.
     */
    private String crlUrl;

    /**
     * Where use thisUpdate and nextUpdate of CRL in the corresponding fields
     * of OCSP response. The default value is true.
     * optional. Default is true
     */
    private boolean useUpdateDatesFromCrl = true;

    /**
     * CA cert file.
     */
    private String caCertFile;

    /**
     * certificate used to verify the CRL signature.
     * Required for indirect CRL, otherwise optional
     */
    private String issuerCertFile;

    /**
     * Folder containing the DER-encoded certificates suffixed with ".der" and ".crt"
     * optional.
     */
    private String certsDir;

    public String getCrlFile() {
      return crlFile;
    }

    public void setCrlFile(String crlFile) {
      this.crlFile = crlFile;
    }

    public String getCrlUrl() {
      return crlUrl;
    }

    public void setCrlUrl(String crlUrl) {
      this.crlUrl = crlUrl;
    }

    public boolean isUseUpdateDatesFromCrl() {
      return useUpdateDatesFromCrl;
    }

    public void setUseUpdateDatesFromCrl(boolean useUpdateDatesFromCrl) {
      this.useUpdateDatesFromCrl = useUpdateDatesFromCrl;
    }

    public String getCaCertFile() {
      return caCertFile;
    }

    public void setCaCertFile(String caCertFile) {
      this.caCertFile = caCertFile;
    }

    public String getIssuerCertFile() {
      return issuerCertFile;
    }

    public void setIssuerCertFile(String issuerCertFile) {
      this.issuerCertFile = issuerCertFile;
    }

    public String getCertsDir() {
      return certsDir;
    }

    public void setCertsDir(String certsDir) {
      this.certsDir = certsDir;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(crlFile, "crlFile");
      notEmpty(caCertFile, "caCertFile");
    }

  }

}
