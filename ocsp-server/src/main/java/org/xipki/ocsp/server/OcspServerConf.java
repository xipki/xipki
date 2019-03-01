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

package org.xipki.ocsp.server;

import java.util.LinkedList;
import java.util.List;

import org.xipki.ocsp.api.OcspStore.SourceConf;
import org.xipki.security.CertpathValidationModel;
import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.InvalidConfException;
import org.xipki.util.TripleState;
import org.xipki.util.ValidatableConf;
import org.xipki.util.Validity;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * TODO.
 * @author Lijun Liao
 */
public class OcspServerConf extends ValidatableConf {

  public enum EmbedCertsMode {
    NONE,
    SIGNER,
    SIGNER_AND_CA;
  }

  public static class CertCollection extends ValidatableConf {

    private String dir;

    private Keystore keystore;

    public String getDir() {
      return dir;
    }

    public void setDir(String value) {
      this.dir = value;
    }

    public Keystore getKeystore() {
      return keystore;
    }

    public void setKeystore(Keystore value) {
      this.keystore = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      exactOne(keystore, "keystore", dir, "dir");
      validate(keystore);
    }

  }

  public static class Keystore extends ValidatableConf {

    private String type;

    private FileOrBinary keystore;

    private String password;

    public String getType() {
      return type;
    }

    public void setType(String value) {
      this.type = value;
    }

    public FileOrBinary getKeystore() {
      return keystore;
    }

    public void setKeystore(FileOrBinary value) {
      this.keystore = value;
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
      validate(keystore);
    }

  }

  public static class Datasource extends ValidatableConf {

    private FileOrValue conf;

    private String name;

    public FileOrValue getConf() {
      return conf;
    }

    public void setConf(FileOrValue value) {
      this.conf = value;
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
      notNull(conf, "conf");
      validate(conf);
    }

  }

  public static class Nonce extends ValidatableConf {

    /**
     * valid values are forbidden, optional and required.
     */
    private TripleState occurrence;

    private Integer minLen;

    private Integer maxLen;

    public TripleState getOccurrence() {
      return occurrence;
    }

    public void setOccurrence(TripleState occurrence) {
      this.occurrence = occurrence;
    }

    public Integer getMinLen() {
      return minLen;
    }

    public void setMinLen(Integer minLen) {
      this.minLen = minLen;
    }

    public Integer getMaxLen() {
      return maxLen;
    }

    public void setMaxLen(Integer maxLen) {
      this.maxLen = maxLen;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(occurrence, "occurrence");
    }

  }

  public static class RequestOption extends ValidatableConf {

    /**
     * Whether to support HTTP GET for small request.
     * The default is false.
     */
    private boolean supportsHttpGet = false;

    /**
     * Maximal count of entries contained in one RequestList.
     */
    private int maxRequestListCount;

    /**
     * Maximal size in byte of a request.
     */
    private int maxRequestSize;

    /**
     * version of the request, current support values are v1.
     */
    private List<String> versions;

    private Nonce nonce;

    private boolean signatureRequired;

    private boolean validateSignature;

    private List<String> hashAlgorithms;

    private CertpathValidation certpathValidation;

    private String name;

    public boolean isSupportsHttpGet() {
      return supportsHttpGet;
    }

    public void setSupportsHttpGet(boolean supportsHttpGet) {
      this.supportsHttpGet = supportsHttpGet;
    }

    public int getMaxRequestListCount() {
      return maxRequestListCount;
    }

    public void setMaxRequestListCount(int maxRequestListCount) {
      this.maxRequestListCount = maxRequestListCount;
    }

    public int getMaxRequestSize() {
      return maxRequestSize;
    }

    public void setMaxRequestSize(int maxRequestSize) {
      this.maxRequestSize = maxRequestSize;
    }

    public List<String> getVersions() {
      return versions;
    }

    public void setVersions(List<String> versions) {
      this.versions = versions;
    }

    public Nonce getNonce() {
      return nonce;
    }

    public void setNonce(Nonce nonce) {
      this.nonce = nonce;
    }

    public boolean isSignatureRequired() {
      return signatureRequired;
    }

    public void setSignatureRequired(boolean signatureRequired) {
      this.signatureRequired = signatureRequired;
    }

    public boolean isValidateSignature() {
      return validateSignature;
    }

    public void setValidateSignature(boolean validateSignature) {
      this.validateSignature = validateSignature;
    }

    public List<String> getHashAlgorithms() {
      if (hashAlgorithms == null) {
        hashAlgorithms = new LinkedList<>();
      }
      return hashAlgorithms;
    }

    public void setHashAlgorithms(List<String> hashAlgorithms) {
      this.hashAlgorithms = hashAlgorithms;
    }

    public CertpathValidation getCertpathValidation() {
      return certpathValidation;
    }

    public void setCertpathValidation(CertpathValidation certpathValidation) {
      this.certpathValidation = certpathValidation;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(versions, "versions");
      notNull(nonce, "nonce");
      validate(nonce);
      validate(certpathValidation);
    }

  }

  public static class CertpathValidation extends ValidatableConf {

    private CertpathValidationModel validationModel;

    private CertCollection trustAnchors;

    private CertCollection certs;

    public CertpathValidationModel getValidationModel() {
      return validationModel;
    }

    public void setValidationModel(CertpathValidationModel validationModel) {
      this.validationModel = validationModel;
    }

    public CertCollection getTrustAnchors() {
      return trustAnchors;
    }

    public void setTrustAnchors(CertCollection trustAnchors) {
      this.trustAnchors = trustAnchors;
    }

    public CertCollection getCerts() {
      return certs;
    }

    public void setCerts(CertCollection certs) {
      this.certs = certs;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(validationModel, "validationModel");
      notNull(trustAnchors, "trustAnchors");
      validate(trustAnchors);
      validate(certs);
    }

  }

  public static class Responder extends ValidatableConf {

    /**
     * To answer OCSP request via URI http://example.com/foo/abc, you can use the combination
     * (servlet.alias = '/', servletPath = '/foo/abc') or
     * (servlet.alias = '/foo', servletPath = '/abc').
     */
    private List<String> servletPaths;

    /**
     * Valid values are RFC2560 and RFC6960. If not present, then RFC6960 mode will be applied.
     */
    private String mode;

    /**
     * Whether to consider certificate as revoked if CA is revoked.
     */
    private boolean inheritCaRevocation;

    private String signer;

    private String request;

    private String response;

    private List<String> stores;

    private String name;

    public List<String> getServletPaths() {
      if (servletPaths == null) {
        servletPaths = new LinkedList<>();
      }
      return servletPaths;
    }

    public void setServletPaths(List<String> servletPaths) {
      this.servletPaths = servletPaths;
    }

    public String getMode() {
      return mode;
    }

    public void setMode(String mode) {
      this.mode = mode;
    }

    public boolean isInheritCaRevocation() {
      return inheritCaRevocation;
    }

    public void setInheritCaRevocation(boolean inheritCaRevocation) {
      this.inheritCaRevocation = inheritCaRevocation;
    }

    public String getSigner() {
      return signer;
    }

    public void setSigner(String signer) {
      this.signer = signer;
    }

    public String getRequest() {
      return request;
    }

    public void setRequest(String request) {
      this.request = request;
    }

    public String getResponse() {
      return response;
    }

    public void setResponse(String response) {
      this.response = response;
    }

    public List<String> getStores() {
      if (stores == null) {
        stores = new LinkedList<>();
      }
      return stores;
    }

    public void setStores(List<String> stores) {
      this.stores = stores;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(servletPaths, "servletPaths");
      notEmpty(signer, "signer");
      notEmpty(request, "request");
      notEmpty(response, "response");
      notEmpty(stores, "stores");
      notEmpty(name, "name");
    }

  }

  public static class ResponseCache extends ValidatableConf {

    private Datasource datasource;

    private int validity = 86400;

    public Datasource getDatasource() {
      return datasource;
    }

    public void setDatasource(Datasource datasource) {
      this.datasource = datasource;
    }

    public int getValidity() {
      return validity;
    }

    public void setValidity(int validity) {
      this.validity = validity;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(datasource, "datasource");
    }

  }

  public static class ResponseOption extends ValidatableConf {

    private boolean responderIdByName = true;

    private boolean includeInvalidityDate = false;

    private boolean includeRevReason = false;

    private EmbedCertsMode embedCertsMode = EmbedCertsMode.SIGNER;

    private boolean includeCerthash = false;

    private Long cacheMaxAge;

    private String name;

    public boolean isResponderIdByName() {
      return responderIdByName;
    }

    public void setResponderIdByName(boolean responderIdByName) {
      this.responderIdByName = responderIdByName;
    }

    public boolean isIncludeInvalidityDate() {
      return includeInvalidityDate;
    }

    public void setIncludeInvalidityDate(boolean includeInvalidityDate) {
      this.includeInvalidityDate = includeInvalidityDate;
    }

    public boolean isIncludeRevReason() {
      return includeRevReason;
    }

    public void setIncludeRevReason(boolean includeRevReason) {
      this.includeRevReason = includeRevReason;
    }

    public EmbedCertsMode getEmbedCertsMode() {
      return embedCertsMode;
    }

    public void setEmbedCertsMode(EmbedCertsMode embedCertsMode) {
      this.embedCertsMode = embedCertsMode;
    }

    public boolean isIncludeCerthash() {
      return includeCerthash;
    }

    public void setIncludeCerthash(boolean includeCerthash) {
      this.includeCerthash = includeCerthash;
    }

    public Long getCacheMaxAge() {
      return cacheMaxAge;
    }

    public void setCacheMaxAge(Long cacheMaxAge) {
      this.cacheMaxAge = cacheMaxAge;
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
    }

  }

  public static class Signer extends ValidatableConf {

    private String name;

    private String type;

    private String key;

    private List<String> algorithms;

    private FileOrBinary cert;

    private List<FileOrBinary> caCerts;

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

    public String getKey() {
      return key;
    }

    public void setKey(String key) {
      this.key = key;
    }

    public List<String> getAlgorithms() {
      if (algorithms == null) {
        algorithms = new LinkedList<>();
      }
      return algorithms;
    }

    public void setAlgorithms(List<String> algorithms) {
      this.algorithms = algorithms;
    }

    public FileOrBinary getCert() {
      return cert;
    }

    public void setCert(FileOrBinary cert) {
      this.cert = cert;
    }

    public List<FileOrBinary> getCaCerts() {
      if (caCerts == null) {
        caCerts = new LinkedList<>();
      }
      return caCerts;
    }

    public void setCaCerts(List<FileOrBinary> caCerts) {
      this.caCerts = caCerts;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
      notEmpty(type, "type");
      notEmpty(key, "key");
      notEmpty(algorithms, "algorithms");
    }

  }

  public static class Store extends ValidatableConf {

    private Source source;

    private Boolean ignoreExpiredCert;

    private Boolean ignoreNotYetValidCert;

    private Integer retentionInterval;

    private Boolean unknownSerialAsGood;

    private Boolean includeArchiveCutoff;

    private Boolean includeCrlId;

    private Validity minNextUpdatePeriod;

    private String name;

    public Source getSource() {
      return source;
    }

    public void setSource(Source source) {
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

    public Validity getMinNextUpdatePeriod() {
      return minNextUpdatePeriod;
    }

    @JSONField(name = "minNextUpdatePeriod")
    public String getMinNextUpdateText() {
      return minNextUpdatePeriod == null ? "" : minNextUpdatePeriod.toString();
    }

    @JSONField(name = "minNextUpdatePeriod")
    public void setMinNextUpdateText(String period) {
      this.minNextUpdatePeriod = period == null ? null : Validity.getInstance(period);
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
      notNull(source, "source");
    }

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
        throw new InvalidConfException(
            "maximal one of dbSource, crlSource and custom may be set");
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

  private ResponseCache responseCache;

  private List<Responder> responders;

  private List<Signer> signers;

  private List<Store> stores;

  private List<Datasource> datasources;

  private List<RequestOption> requestOptions;

  private List<ResponseOption> responseOptions;

  private boolean master = true;

  public ResponseCache getResponseCache() {
    return responseCache;
  }

  public void setResponseCache(ResponseCache responseCache) {
    this.responseCache = responseCache;
  }

  public List<Responder> getResponders() {
    if (responders == null) {
      responders = new LinkedList<>();
    }
    return responders;
  }

  public void setResponders(List<Responder> responders) {
    this.responders = responders;
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

  public List<Store> getStores() {
    if (stores == null) {
      stores = new LinkedList<>();
    }
    return stores;
  }

  public void setStores(List<Store> stores) {
    this.stores = stores;
  }

  public List<Datasource> getDatasources() {
    if (datasources == null) {
      datasources = new LinkedList<>();
    }
    return datasources;
  }

  public void setDatasources(List<Datasource> datasources) {
    this.datasources = datasources;
  }

  public List<RequestOption> getRequestOptions() {
    if (requestOptions == null) {
      requestOptions = new LinkedList<>();
    }
    return requestOptions;
  }

  public void setRequestOptions(List<RequestOption> requestOptions) {
    this.requestOptions = requestOptions;
  }

  public List<ResponseOption> getResponseOptions() {
    if (responseOptions == null) {
      responseOptions = new LinkedList<>();
    }
    return responseOptions;
  }

  public void setResponseOptions(List<ResponseOption> responseOptions) {
    this.responseOptions = responseOptions;
  }

  public boolean isMaster() {
    return master;
  }

  public void setMaster(boolean master) {
    this.master = master;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(responders, "responders");
    validate(responders);

    notEmpty(signers, "signers");
    validate(signers);

    notEmpty(stores, "stores");
    validate(stores);

    validate(datasources);

    notEmpty(requestOptions, "requestOptions");
    validate(requestOptions);

    notEmpty(responseOptions, "responseOptions");
    validate(responseOptions);
  }

}
