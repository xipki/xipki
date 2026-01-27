// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.ocsp.api.CertStatusInfo.UnknownCertBehaviour;
import org.xipki.ocsp.api.CertStatusInfo.UnknownIssuerBehaviour;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.security.CertPathValidationModel;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataSourceConf;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.extra.type.Validity.Unit;
import org.xipki.util.io.FileOrBinary;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Configuration of OCSP server.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspServerConf {

  public enum EmbedCertsMode {
    NONE,
    SIGNER,
    SIGNER_AND_CA
  } // class EmbedCertsMode

  public static class CertCollection {

    private final String dir;

    private final FileOrBinary[] certs;

    public CertCollection(String dir) {
      this.dir = Args.notBlank(dir, "dir");
      this.certs = null;
    }

    public CertCollection(FileOrBinary[] certs) {
      this.dir = null;
      this.certs = Args.notNull(certs, "certs");
    }

    public String getDir() {
      return dir;
    }

    public FileOrBinary[] getCerts() {
      return certs;
    }

    public static CertCollection parse(JsonMap json) throws CodecException {
      String dir = json.getString("dir");
      FileOrBinary[] certs = FileOrBinary.parseArray(json.getList("certs"));
      Args.exactOne(dir, "dir", certs, "certs");
      return (dir != null) ? new CertCollection(dir)
          : new CertCollection(certs);
    }

  } // class CertCollection

  public static class Nonce {

    /**
     * valid values are ignore, forbidden, optional and required.
     */
    private final QuadrupleState occurrence;

    private final Integer minLen;

    private final Integer maxLen;

    public Nonce(QuadrupleState occurrence, Integer minLen, Integer maxLen) {
      this.occurrence = Args.notNull(occurrence, "occurrence");
      this.minLen = minLen;
      this.maxLen = maxLen;
    }

    public QuadrupleState getOccurrence() {
      return occurrence;
    }

    public Integer getMinLen() {
      return minLen;
    }

    public Integer getMaxLen() {
      return maxLen;
    }

    public static Nonce parse(JsonMap json) throws CodecException {
      return new Nonce(
          json.getNnEnum("occurrence", QuadrupleState.class),
          json.getInt("minLen"), json.getInt("maxLen"));
    }

  } // class Nonce

  public static class RequestOption {

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

    private final String name;

    /**
     * version of the request, current support values are v1.
     */
    private final List<String> versions;

    private final Nonce nonce;

    private boolean signatureRequired;

    private boolean validateSignature;

    private List<String> hashAlgorithms;

    private CertpathValidation certpathValidation;

    public RequestOption(String name, List<String> versions, Nonce nonce) {
      this.name = Args.notBlank(name, "name");
      this.versions = Args.notEmpty(versions, "versions");
      this.nonce = Args.notNull(nonce, "nonce");
    }

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

    public Nonce getNonce() {
      return nonce;
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

    public static RequestOption parse(JsonMap json) throws CodecException {
      RequestOption ret = new RequestOption(
          json.getNnString("name"), json.getNnStringList("versions"),
          Nonce.parse(json.getNnMap("nonce")));

      ret.setSupportsHttpGet(json.getBool("supportsHttpGet", false));
      ret.setSignatureRequired(json.getBool("signatureRequired", false));
      ret.setValidateSignature(json.getBool("validateSignature", false));
      ret.setHashAlgorithms(json.getStringList("hashAlgorithms"));

      Integer i = json.getInt("maxRequestListCount");
      if (i != null) {
        ret.setMaxRequestListCount(i);
      }

      i = json.getInt("maxRequestSize");
      if (i != null) {
        ret.setMaxRequestSize(i);
      }

      JsonMap map = json.getMap("certpathValidation");
      if (map != null) {
        ret.setCertpathValidation(CertpathValidation.parse(map));
      }

      return ret;
    }

  } // class RequestOption

  public static class CertpathValidation {

    private final CertPathValidationModel validationModel;

    private final CertCollection trustanchors;

    private final CertCollection certs;

    public CertpathValidation(
        CertPathValidationModel validationModel,
        CertCollection trustanchors, CertCollection certs) {
      this.validationModel = Args.notNull(validationModel, "validationModel");
      this.trustanchors    = Args.notNull(trustanchors, "trustanchors");
      this.certs = certs;
    }

    public CertPathValidationModel getValidationModel() {
      return validationModel;
    }

    public CertCollection getTrustanchors() {
      return trustanchors;
    }

    public CertCollection getCerts() {
      return certs;
    }

    public static CertpathValidation parse(JsonMap json)
        throws CodecException {
      JsonMap map = json.getMap("certs");
      CertCollection certs = null;
      if (map != null) {
        certs = CertCollection.parse(map);
      }

      return new CertpathValidation(
          json.getNnEnum("validationModel", CertPathValidationModel.class),
          CertCollection.parse(json.getNnMap("trustanchors")), certs);
    }

  } // class CertpathValidation

  public static class Responder {

    /**
     * To answer OCSP request via URI http://myorg.com/foo/abc, you can use the
     * combination
     * (servlet.alias = '/', servletPath = '/foo/abc') or
     * (servlet.alias = '/foo', servletPath = '/abc').
     */
    private final List<String> servletPaths;

    /**
     * Valid values are RFC2560 and RFC6960. If not present, then RFC6960 mode
     * will be applied.
     */
    private final String mode;

    /**
     * Whether to consider certificate as revoked if CA is revoked.
     */
    private final boolean inheritCaRevocation;

    private final String signer;

    private final String request;

    private final String response;

    private final List<String> stores;

    private final String name;

    public Responder(String name, String mode, List<String> servletPaths,
                     boolean inheritCaRevocation, String signer,
                     String request, String response, List<String> stores) {
      this.name     = Args.notBlank(name, "name");
      this.signer   = Args.notBlank(signer, "signer");
      this.request  = Args.notBlank(request, "request");
      this.response = Args.notBlank(response, "response");
      this.stores   = Args.notEmpty(stores, "stores");
      this.servletPaths = Args.notEmpty(servletPaths, "servletPaths");

      this.mode = mode;
      this.inheritCaRevocation = inheritCaRevocation;
    }

    public List<String> getServletPaths() {
      return servletPaths;
    }

    public String getMode() {
      return mode;
    }

    public boolean isInheritCaRevocation() {
      return inheritCaRevocation;
    }

    public String getSigner() {
      return signer;
    }

    public String getRequest() {
      return request;
    }

    public String getResponse() {
      return response;
    }

    public List<String> getStores() {
      return stores;
    }

    public String getName() {
      return name;
    }

    public static Responder parse(JsonMap json) throws CodecException {
      return new Responder(json.getString("name"),
          json.getString("mode"), json.getStringList("servletPaths"),
          json.getBool("inheritCaRevocation", false),
          json.getString("signer"),   json.getString("request"),
          json.getString("response"), json.getStringList("stores"));
    }

  } // class Responder

  public static class ResponseCache {

    private final DataSourceConf datasource;

    private final Validity validity;

    public ResponseCache(DataSourceConf datasource, Validity validity) {
      this.datasource = Args.notNull(datasource, "datasource");
      this.validity = validity;
    }

    public DataSourceConf getDatasource() {
      return datasource;
    }

    public Validity getValidity() {
      return validity == null ? new Validity(1, Unit.DAY) : validity;
    }

    public static ResponseCache parse(JsonMap json) throws CodecException {
      String str = json.getString("validity");
      Validity validity = str == null ? null : Validity.getInstance(str);

      return new ResponseCache(
          DataSourceConf.parse(json.getMap("datasource")), validity);
    }

  } // class ResponseCache

  public static class ResponseOption {

    private final String name;

    private boolean responderIdByName = true;

    private boolean includeInvalidityDate = false;

    private boolean includeRevReason = false;

    private EmbedCertsMode embedCertsMode = EmbedCertsMode.SIGNER;

    private boolean includeCerthash = false;

    private Long cacheMaxAge;

    public ResponseOption(String name) {
      this.name = Args.notBlank(name, "name");
    }

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

    public static ResponseOption parse(JsonMap json) throws CodecException {
      ResponseOption ret = new ResponseOption(json.getNnString("name"));

      Boolean b = json.getBool("responderIdByName");
      if (b != null) {
        ret.setResponderIdByName(b);
      }

      b = json.getBool("includeInvalidityDate");
      if (b != null) {
        ret.setIncludeInvalidityDate(b);
      }

      b = json.getBool("includeRevReason");
      if (b != null) {
        ret.setIncludeRevReason(b);
      }

      b = json.getBool("includeCerthash");
      if (b != null) {
        ret.setIncludeCerthash(b);
      }

      ret.setCacheMaxAge(json.getLong("cacheMaxAge"));

      EmbedCertsMode certsMode = json.getEnum("embedCertsMode",
          EmbedCertsMode.class);
      if (certsMode != null) {
        ret.setEmbedCertsMode(certsMode);
      }

      return ret;
    }

  } // class ResponseOption

  public static class Signer {

    private final String name;

    private final String type;

    private final String key;

    private final List<String> algorithms;

    private final FileOrBinary cert;

    private final List<FileOrBinary> caCerts;

    public Signer(String name, String type, String key,
                  List<String> algorithms, FileOrBinary cert,
                  List<FileOrBinary> caCerts) {
      this.name = Args.notBlank(name, "name");
      this.type = Args.notBlank(type, "type");
      this.key  = Args.notBlank(key, "key");
      this.algorithms = algorithms;
      this.cert = cert;
      this.caCerts = (caCerts == null) ? Collections.emptyList() : caCerts;
    }

    public String getName() {
      return name;
    }

    public String getType() {
      return type;
    }

    public String getKey() {
      return key;
    }

    public List<String> getAlgorithms() {
      return algorithms;
    }

    public FileOrBinary getCert() {
      return cert;
    }

    public List<FileOrBinary> getCaCerts() {
      return caCerts;
    }

    public static Signer parse(JsonMap json) throws CodecException {
      return new Signer(json.getNnString("name"),
          json.getNnString("type"), json.getNnString("key"),
          json.getStringList("algorithms"),
          FileOrBinary.parse(json.getMap("cert")),
          FileOrBinary.parseList(json.getList("caCerts")));
    }

  } // class Signer

  public static class Store {

    private final String name;

    private final String minNextUpdatePeriod;

    private final String maxNextUpdatePeriod;

    private final Source source;

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

    public Store(String name, Source source, String minNextUpdatePeriod,
                 String maxNextUpdatePeriod) {
      this.name = Args.notBlank(name, "name");
      this.source = Args.notNull(source, "source");

      if (minNextUpdatePeriod != null && maxNextUpdatePeriod != null) {
        Validity min = Validity.getInstance(minNextUpdatePeriod);
        Validity max = Validity.getInstance(maxNextUpdatePeriod);
        if (min.compareTo(max) > 0) {
          throw new IllegalArgumentException(String.format(
              "minNextUpdatePeriod (%s) > maxNextUpdatePeriod (%s) is not " +
                  "allowed", minNextUpdatePeriod, maxNextUpdatePeriod));
        }
      }

      this.minNextUpdatePeriod = minNextUpdatePeriod;
      this.maxNextUpdatePeriod = maxNextUpdatePeriod;
    }

    public Source getSource() {
      return source;
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

    public void setUnknownCertBehaviour(
        UnknownCertBehaviour unknownCertBehaviour) {
      this.unknownCertBehaviour = unknownCertBehaviour;
    }

    public String getMinNextUpdatePeriod() {
      return minNextUpdatePeriod;
    }

    public String getMaxNextUpdatePeriod() {
      return maxNextUpdatePeriod;
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

    public String getUpdateInterval() {
      return updateInterval;
    }

    public void setUpdateInterval(String updateInterval) {
      this.updateInterval = updateInterval;
    }

    public static Store parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("source");
      Source source = (map == null) ? null : Source.parse(map);
      Store ret = new Store(json.getString("name"), source,
          json.getString("minNextUpdatePeriod"),
          json.getString("maxNextUpdatePeriod"));

      ret.setUpdateInterval(json.getString("updateInterval"));
      ret.setIgnoreNotYetValidCert(json.getBool("ignoreNotYetValidCert"));
      ret.setIgnoreExpiredCert(json.getBool("ignoreExpiredCert"));
      ret.setRetentionInterval(json.getInt("retentionInterval"));

      String str = json.getString("unknownCertBehaviour");
      if (str != null) {
        ret.setUnknownCertBehaviour(UnknownCertBehaviour.valueOf(str));
      }

      ret.setIncludeArchiveCutoff(json.getBool("includeArchiveCutoff"));
      ret.setIncludeCrlId(json.getBool("includeCrlId"));

      return ret;
    }

  } // class Store

  public static class Source {

    private final String type;

    private final String datasource;

    private final JsonMap conf;

    public Source(String type, String datasource, JsonMap conf) {
      this.datasource = datasource;
      this.type = Args.notBlank(type, "type");
      this.conf = Args.notNull(conf, "conf");
    }

    public String getType() {
      return type;
    }

    public String getDatasource() {
      return datasource;
    }

    public JsonMap getConf() {
      return conf;
    }

    public static Source parse(JsonMap json) throws CodecException {
      return new Source(json.getString("type"),
          json.getString("datasource"), json.getMap("conf"));
    }

  } // class Source

  public static class CaCerts {

    /**
     * Files of CA certificates to be considered.<br/>
     * optional. Default is all.
     */
    private final List<String> includes;

    /**
     * Comma-separated files of CA certificates to be not considered
     * optional. Default is none.
     */
    private final List<String> excludes;

    public CaCerts(List<String> includes, List<String> excludes) {
      this.includes = includes;
      this.excludes = excludes;
    }

    public List<String> getIncludes() {
      return includes;
    }

    public List<String> getExcludes() {
      return excludes;
    }

    public static CaCerts parse(JsonMap json) throws CodecException {
      return new CaCerts(json.getStringList("includes"),
          json.getStringList("excludes"));
    }

    public static CaCerts parseSourceConf(JsonMap sourceConf)
        throws OcspStoreException {
      try {
        JsonMap map = sourceConf.getMap("caCerts");
        return map == null ? null : OcspServerConf.CaCerts.parse(map);
      } catch (CodecException e) {
        throw new OcspStoreException(
            "error parsing caCerts: " + e.getMessage(), e);
      }
    }

  } // class CaCerts

  private final ResponseCache responseCache;

  private final List<Responder> responders;

  private final List<Signer> signers;

  private final List<Store> stores;

  private final List<DataSourceConf> datasources;

  private final List<RequestOption> requestOptions;

  private final List<ResponseOption> responseOptions;

  private boolean master = true;

  public OcspServerConf(ResponseCache responseCache,
                        List<Responder> responders,
                        List<Signer> signers, List<Store> stores,
                        List<DataSourceConf> datasources,
                        List<RequestOption> requestOptions,
                        List<ResponseOption> responseOptions) {
    this.responseCache = responseCache;
    this.datasources   = (datasources == null) ? Collections.emptyList()
        : datasources;
    this.responders    = Args.notEmpty(responders, "responders");
    this.signers       = Args.notEmpty(signers, "signers");
    this.stores        = Args.notEmpty(stores, "stores");
    this.requestOptions  = Args.notEmpty(requestOptions, "requestOptions");
    this.responseOptions = Args.notEmpty(responseOptions, "responseOptions");

  }

  private UnknownIssuerBehaviour unknownIssuerBehaviour =
      UnknownIssuerBehaviour.unknown;

  public static OcspServerConf readConfFromFile(String fileName)
      throws InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try {
      JsonMap root = JsonParser.parseMap(Paths.get(fileName), true);
      return parse(root);
    } catch (CodecException | RuntimeException e) {
      throw new InvalidConfException("error parsing file " + fileName + ": " +
          e.getMessage(), e);
    }
  }

  public static OcspServerConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("responseCache");
    ResponseCache responseCache = (map == null) ? null
        : ResponseCache.parse(map);

    JsonList list = json.getList("responders");
    List<Responder> responders = null;
    if (list != null) {
      responders = new ArrayList<>(list.size());
      for (JsonMap m : list.toMapList()) {
        responders.add(Responder.parse(m));
      }
    }

    list = json.getList("signers");
    List<Signer> signers = null;
    if (list != null) {
      signers = new ArrayList<>(list.size());
      for (JsonMap m : list.toMapList()) {
        signers.add(Signer.parse(m));
      }
    }

    list = json.getList("stores");
    List<Store> stores = null;
    if (list != null) {
      stores = new ArrayList<>(list.size());
      for (JsonMap m : list.toMapList()) {
        stores.add(Store.parse(m));
      }
    }

    List<DataSourceConf> datasources =
        DataSourceConf.parseList(json.getList("datasources"));

    list = json.getList("requestOptions");
    List<RequestOption> requestOptions = null;
    if (list != null) {
      requestOptions = new ArrayList<>(list.size());
      for (JsonMap m : list.toMapList()) {
        requestOptions.add(RequestOption.parse(m));
      }
    }

    list = json.getList("responseOptions");
    List<ResponseOption> responseOptions = null;
    if (list != null) {
      responseOptions = new ArrayList<>(list.size());
      for (JsonMap m : list.toMapList()) {
        responseOptions.add(ResponseOption.parse(m));
      }
    }

    OcspServerConf ret =  new OcspServerConf(responseCache, responders,
        signers, stores, datasources, requestOptions, responseOptions);

    Boolean b = json.getBool("master");
    if (b != null) {
      ret.setMaster(b);
    }

    UnknownIssuerBehaviour behaviour = json.getEnum(
        "unknownIssuerBehaviour", UnknownIssuerBehaviour.class);
    if (behaviour != null) {
      ret.setUnknownIssuerBehaviour(behaviour);
    }

    return ret;
  }

  public ResponseCache getResponseCache() {
    return responseCache;
  }

  public List<Responder> getResponders() {
    return responders;
  }

  public List<Signer> getSigners() {
    return signers;
  }

  public List<Store> getStores() {
    return stores;
  }

  public List<DataSourceConf> getDatasources() {
    return datasources;
  }

  public List<RequestOption> getRequestOptions() {
    return requestOptions;
  }

  public List<ResponseOption> getResponseOptions() {
    return responseOptions;
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

  public void setUnknownIssuerBehaviour(
      UnknownIssuerBehaviour unknownIssuerBehaviour) {
    this.unknownIssuerBehaviour = unknownIssuerBehaviour;
  }

}
