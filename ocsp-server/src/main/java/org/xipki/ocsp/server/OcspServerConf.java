// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.datasource.DataSourceConf;
import org.xipki.ocsp.api.CertStatusInfo.UnknownCertBehaviour;
import org.xipki.ocsp.api.CertStatusInfo.UnknownIssuerBehaviour;
import org.xipki.security.CertpathValidationModel;
import org.xipki.security.util.JSON;
import org.xipki.util.FileOrBinary;
import org.xipki.util.ValidatableConf;
import org.xipki.util.Validity;
import org.xipki.util.Validity.Unit;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Configuration of OCSP server.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspServerConf extends ValidatableConf {

  public enum EmbedCertsMode {
    NONE,
    SIGNER,
    SIGNER_AND_CA
  } // class EmbedCertsMode

  public static class CertCollection extends ValidatableConf {

    private String dir;

    private FileOrBinary[] certs;

    public String getDir() {
      return dir;
    }

    public void setDir(String value) {
      this.dir = value;
    }

    public FileOrBinary[] getCerts() {
      return certs;
    }

    public void setCerts(FileOrBinary[] certs) {
      this.certs = certs;
    }

    @Override
    public void validate() throws InvalidConfException {
      exactOne(certs, "certs", dir, "dir");
    }

  } // class CertCollection

  public static class Nonce extends ValidatableConf {

    /**
     * valid values are ignore, forbidden, optional and required.
     */
    private QuadrupleState occurrence;

    private Integer minLen;

    private Integer maxLen;

    public QuadrupleState getOccurrence() {
      return occurrence;
    }

    public void setOccurrence(QuadrupleState occurrence) {
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

  } // class Nonce

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
      validate(nonce, certpathValidation);
    }

  } // class RequestOption

  public static class CertpathValidation extends ValidatableConf {

    private CertpathValidationModel validationModel;

    private CertCollection trustanchors;

    private CertCollection certs;

    public CertpathValidationModel getValidationModel() {
      return validationModel;
    }

    public void setValidationModel(CertpathValidationModel validationModel) {
      this.validationModel = validationModel;
    }

    public CertCollection getTrustanchors() {
      return trustanchors;
    }

    public void setTrustanchors(CertCollection trustanchors) {
      this.trustanchors = trustanchors;
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
      notNull(trustanchors, "trustanchors");
      validate(trustanchors, certs);
    }

  } // class CertpathValidation

  public static class Responder extends ValidatableConf {

    /**
     * To answer OCSP request via URI http://myorg.com/foo/abc, you can use the combination
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
      notBlank(signer, "signer");
      notBlank(request, "request");
      notBlank(response, "response");
      notEmpty(stores, "stores");
      notBlank(name, "name");
    }

  } // class Responder

  public static class ResponseCache extends ValidatableConf {

    private DataSourceConf datasource;

    private String validity;

    public DataSourceConf getDatasource() {
      return datasource;
    }

    public void setDatasource(DataSourceConf datasource) {
      this.datasource = datasource;
    }

    public String getValidity() {
      return validity;
    }

    public void setValidity(String validity) {
      this.validity = validity;
    }

    public Validity validity() {
      return validity == null ? new Validity(1, Unit.DAY) : Validity.getInstance(validity);
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(datasource, "datasource");
    }

  } // class ResponseCache

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
      notBlank(name, "name");
    }

  } // class ResponseOption

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
      notBlank(name, "name");
      notBlank(type, "type");
      notBlank(key, "key");
      notEmpty(algorithms, "algorithms");
    }

  } // class Signer

  public static class Store extends ValidatableConf {

    private Source source;

    /**
     * Update interval. Either "NEVER" or {@link Validity}.
     */
    private String updateInterval;

    private Boolean ignoreExpiredCert;

    private Boolean ignoreNotYetValidCert;

    private Integer retentionInterval;

    private UnknownCertBehaviour unknownCertBehaviour;

    private Boolean includeArchiveCutoff;

    private Boolean includeCrlId;

    private String minNextUpdatePeriod;

    private String maxNextUpdatePeriod;

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

    public UnknownCertBehaviour getUnknownCertBehaviour() {
      return unknownCertBehaviour;
    }

    public void setUnknownCertBehaviour(UnknownCertBehaviour unknownCertBehaviour) {
      this.unknownCertBehaviour = unknownCertBehaviour;
    }

    public void setMinNextUpdatePeriod(String minNextUpdatePeriod) {
      this.minNextUpdatePeriod = minNextUpdatePeriod;
    }

    public String getMinNextUpdatePeriod() {
      return minNextUpdatePeriod;
    }

    public String getMaxNextUpdatePeriod() {
      return maxNextUpdatePeriod;
    }

    public void setMaxNextUpdatePeriod(String maxNextUpdatePeriod) {
      this.maxNextUpdatePeriod = maxNextUpdatePeriod;
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

    public String getUpdateInterval() {
      return updateInterval;
    }

    public void setUpdateInterval(String updateInterval) {
      this.updateInterval = updateInterval;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notNull(source, "source");

      if (minNextUpdatePeriod != null && maxNextUpdatePeriod != null) {
        try {
          Validity min = Validity.getInstance(minNextUpdatePeriod);
          Validity max = Validity.getInstance(maxNextUpdatePeriod);
          if (min.compareTo(max) > 0) {
            throw new InvalidConfException(String.format(
                    "minNextUpdatePeriod (%s) > maxNextUpdatePeriod (%s) is not allowed",
                    minNextUpdatePeriod, maxNextUpdatePeriod));
          }
        } catch (IllegalArgumentException ex) {
          throw new InvalidConfException(ex.getMessage());
        }
      }
    }

  } // class Store

  public static class Source extends ValidatableConf {

    private String type;

    private String datasource;

    private Map<String, ? extends Object> conf;

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

    public Map<String, ?> getConf() {
      return conf;
    }

    public void setConf(Map<String, ?> value) {
      this.conf = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(type, "type");
    }

  } // class Source

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

  } // class CaCerts

  private ResponseCache responseCache;

  private List<Responder> responders;

  private List<Signer> signers;

  private List<Store> stores;

  private List<DataSourceConf> datasources;

  private List<RequestOption> requestOptions;

  private List<ResponseOption> responseOptions;

  private boolean master = true;

  private UnknownIssuerBehaviour unknownIssuerBehaviour = UnknownIssuerBehaviour.unknown;

  public static OcspServerConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      OcspServerConf conf = JSON.parseObject(is, OcspServerConf.class);
      conf.validate();

      return conf;
    }
  }

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

  public List<DataSourceConf> getDatasources() {
    if (datasources == null) {
      datasources = new LinkedList<>();
    }
    return datasources;
  }

  public void setDatasources(List<DataSourceConf> datasources) {
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

  public UnknownIssuerBehaviour getUnknownIssuerBehaviour() {
    return unknownIssuerBehaviour;
  }

  public void setUnknownIssuerBehaviour(UnknownIssuerBehaviour unknownIssuerBehaviour) {
    this.unknownIssuerBehaviour = unknownIssuerBehaviour;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(responders, "responders");
    notEmpty(signers, "signers");
    notEmpty(stores, "stores");
    notEmpty(requestOptions, "requestOptions");
    notEmpty(responseOptions, "responseOptions");

    validate(responders, signers, stores, datasources, requestOptions, responseOptions);
  } // method validate

}
