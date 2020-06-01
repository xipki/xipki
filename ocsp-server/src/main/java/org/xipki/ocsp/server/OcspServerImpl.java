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

package org.xipki.ocsp.server;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceConf;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusInfo.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo.UnknownIssuerBehaviour;
import org.xipki.ocsp.api.OcspRespWithCacheInfo;
import org.xipki.ocsp.api.OcspRespWithCacheInfo.ResponseCacheInfo;
import org.xipki.ocsp.api.OcspServer;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.ocsp.api.Responder;
import org.xipki.ocsp.api.ResponderAndPath;
import org.xipki.ocsp.server.OcspServerConf.EmbedCertsMode;
import org.xipki.ocsp.server.OcspServerConf.Source;
import org.xipki.ocsp.server.ResponderOption.OcspMode;
import org.xipki.ocsp.server.store.CaDbCertStatusStore;
import org.xipki.ocsp.server.store.CrlDbCertStatusStore;
import org.xipki.ocsp.server.store.DbCertStatusStore;
import org.xipki.ocsp.server.store.ResponseCacher;
import org.xipki.ocsp.server.store.ejbca.EjbcaCertStatusStore;
import org.xipki.ocsp.server.type.CertID;
import org.xipki.ocsp.server.type.EncodingException;
import org.xipki.ocsp.server.type.ExtendedExtension;
import org.xipki.ocsp.server.type.Extension;
import org.xipki.ocsp.server.type.Extensions;
import org.xipki.ocsp.server.type.OID;
import org.xipki.ocsp.server.type.OcspRequest;
import org.xipki.ocsp.server.type.ResponderID;
import org.xipki.ocsp.server.type.TaggedCertSequence;
import org.xipki.ocsp.server.type.WritableOnlyExtension;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.AlgorithmCode;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CertpathValidationModel;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.NoIdleSignerException;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.Hex;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;

import com.alibaba.fastjson.JSON;

/**
 * Implementation of {@link OcspServer}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspServerImpl implements OcspServer {

  private static class SizeComparableString implements Comparable<SizeComparableString> {

    private String str;

    public SizeComparableString(String str) {
      this.str = Args.notNull(str, "str");
    }

    @Override
    public int compareTo(SizeComparableString obj) {
      if (str.length() == obj.str.length()) {
        return 0;
      }

      return (str.length() > obj.str.length()) ? 1 : -1;
    }

  } // class SizeComparableString

  private static class OcspRespControl {
    boolean canCacheInfo;
    boolean includeExtendedRevokeExtension;
    long cacheNextUpdate;

    public OcspRespControl() {
      includeExtendedRevokeExtension = false;
      cacheNextUpdate = Long.MAX_VALUE;
    }
  } // class OcspRespControl

  public static final long DFLT_CACHE_MAX_AGE = 60; // 1 minute

  private static final String STORE_TYPE_XIPKI_DB = "xipki-db";

  private static final String STORE_TYPE_XIPKI_CA_DB = "xipki-ca-db";

  private static final String STORE_TYPE_CRL = "crl";

  private static final String STORE_TYPE_EJBCA_DB = "ejbca-db";

  private static final byte[] DERNullBytes = new byte[]{0x05, 0x00};

  private static final byte[] bytes_certstatus_good = new byte[]{(byte) 0x80, 0x00};

  private static final byte[] bytes_certstatus_unknown = new byte[]{(byte) 0x82, 0x00};

  private static final byte[] bytes_certstatus_rfc6960_unknown =
      Hex.decode("a116180f31393730303130313030303030305aa0030a0106");

  private static final WritableOnlyExtension extension_pkix_ocsp_extendedRevoke;

  private static final Logger LOG = LoggerFactory.getLogger(OcspServerImpl.class);

  private static final Map<OcspResponseStatus, OcspRespWithCacheInfo> unsuccesfulOCSPRespMap;

  private static final byte[] encodedAcceptableResponses_Basic;

  private static final String version;

  private final DataSourceFactory datasourceFactory;

  private SecurityFactory securityFactory;

  private String confFile;

  private boolean master;

  private UnknownIssuerBehaviour unknownIssuerBehaviour = UnknownIssuerBehaviour.unknown;

  private ResponseCacher responseCacher;

  private Map<String, ResponderImpl> responders = new HashMap<>();

  private Map<String, ResponseSigner> signers = new HashMap<>();

  private Map<String, RequestOption> requestOptions = new HashMap<>();

  private Map<String, OcspServerConf.ResponseOption> responseOptions = new HashMap<>();

  private Map<String, OcspStore> stores = new HashMap<>();

  private List<String> servletPaths = new ArrayList<>();

  private Map<String, ResponderImpl> path2responderMap = new HashMap<>();

  private AtomicBoolean initialized = new AtomicBoolean(false);

  static {
    unsuccesfulOCSPRespMap = new HashMap<>(10);
    for (OcspResponseStatus status : OcspResponseStatus.values()) {
      if (status == OcspResponseStatus.successful) {
        continue;
      }
      OCSPResponse resp = new OCSPResponse(
          new org.bouncycastle.asn1.ocsp.OCSPResponseStatus(status.getStatus()), null);
      byte[] encoded;
      try {
        encoded = resp.getEncoded();
      } catch (IOException ex) {
        throw new ExceptionInInitializerError(
            "could not encode OCSPResp for status " + status + ": " + ex.getMessage());
      }
      unsuccesfulOCSPRespMap.put(status, new OcspRespWithCacheInfo(encoded, null));
    }

    ExtendedExtension ext = new ExtendedExtension(OID.ID_PKIX_OCSP_EXTENDEDREVOKE,
        false, DERNullBytes);
    byte[] encoded = new byte[ext.getEncodedLength()];
    ext.write(encoded, 0);
    extension_pkix_ocsp_extendedRevoke = new WritableOnlyExtension(encoded);

    encodedAcceptableResponses_Basic = Hex.decode("300B06092B0601050507300101");

    String ver;
    try {
      ver = new String(IoUtil.read(OcspServerImpl.class.getResourceAsStream("/version"))).trim();
    } catch (Exception ex) {
      ver = "UNKNOWN";
    }
    version = ver;
  } // method static

  public OcspServerImpl() {
    LOG.info("XiPKI OCSP Responder version {}", version);
    this.datasourceFactory = new DataSourceFactory();
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  public void setConfFile(String confFile) {
    this.confFile = confFile;
  }

  @Override
  public ResponderAndPath getResponderForPath(String path) throws UnsupportedEncodingException {
    for (String servletPath : servletPaths) {
      if (path.startsWith(servletPath)) {
        return new ResponderAndPath(servletPath, path2responderMap.get(servletPath));
      }
    }
    return null;
  }

  public ResponderImpl getResponder(String name) {
    Args.notBlank(name, "name");
    return responders.get(name);
  }

  public boolean isInitialized() {
    return initialized.get();
  }

  public void init() throws InvalidConfException, DataAccessException, PasswordResolverException {
    init(true);
  }

  public void init(boolean force) throws InvalidConfException, PasswordResolverException {
    LOG.info("starting OCSPResponder server ...");
    if (initialized.get()) {
      if (!force) {
        LOG.info("already started, skipping ...");
        return;
      }
    }

    try {
      init0();
      initialized.set(true);
      LOG.info("started OCSPResponder server");
    } catch (InvalidConfException | PasswordResolverException ex) {
      LOG.error("could not start OCSP responder", ex);
      throw ex;
    } catch (Error ex) {
      LOG.error("could not start OCSP responder", ex);
      throw ex;
    } catch (RuntimeException ex) {
      LOG.error("could not start OCSP responder", ex);
      throw ex;
    } catch (Throwable th) {
      LOG.error("could not start OCSP responder", th);
      throw new IllegalStateException(th);
    }
  } // method init

  private void init0() throws OcspStoreException, InvalidConfException, PasswordResolverException {
    if (confFile == null) {
      throw new IllegalStateException("confFile is not set");
    }
    if (datasourceFactory == null) {
      throw new IllegalStateException("datasourceFactory is not set");
    }
    if (securityFactory == null) {
      throw new IllegalStateException("securityFactory is not set");
    }

    initialized.set(false);

    // reset
    responseCacher = null;
    responders.clear();
    signers.clear();

    requestOptions.clear();
    responseOptions.clear();
    for (String name : stores.keySet()) {
      OcspStore store = stores.get(name);
      try {
        store.close();
      } catch (IOException ex) {
        throw new OcspStoreException("could not close OCSP store " + name, ex);
      }
    }
    stores.clear();

    servletPaths.clear();
    path2responderMap.clear();

    OcspServerConf conf = parseConf(confFile);

    //-- check the duplication names
    Set<String> set = new HashSet<>();

    // Duplication name check: responder
    for (OcspServerConf.Responder m : conf.getResponders()) {
      String name = m.getName();

      if ("health".equalsIgnoreCase(name) || "mgmt".equalsIgnoreCase(name)) {
        throw new InvalidConfException("responder name '" + name + "' is not permitted");
      }

      if (set.contains(name)) {
        throw new InvalidConfException("duplicated definition of responder named '" + name + "'");
      }

      if (StringUtil.isBlank(name)) {
        throw new InvalidConfException("responder name may not be empty");
      }

      for (int i = 0; i < name.length(); i++) {
        char ch = name.charAt(i);
        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z')
            || (ch >= 'a' && ch <= 'z') || ch == '-') || ch == '_' || ch == '.') {
          throw new InvalidConfException("invalid OCSP responder name '" + name + "'");
        }
      } // end for
      set.add(name);
    } // end for

    // Duplication name check: signer
    set.clear();
    for (OcspServerConf.Signer m : conf.getSigners()) {
      String name = m.getName();
      if (set.contains(name)) {
        throw new InvalidConfException(
            "duplicated definition of signer option named '" + name + "'");
      }
      set.add(name);
    }

    // Duplication name check: requests
    set.clear();
    for (OcspServerConf.RequestOption m : conf.getRequestOptions()) {
      String name = m.getName();
      if (set.contains(name)) {
        throw new InvalidConfException(
            "duplicated definition of request option named '" + name + "'");
      }
      set.add(name);
    }

    // Duplication name check: response
    set.clear();
    for (OcspServerConf.ResponseOption m : conf.getResponseOptions()) {
      String name = m.getName();
      if (set.contains(name)) {
        throw new InvalidConfException(
            "duplicated definition of response option named '" + name + "'");
      }
      set.add(name);
    }

    // Duplication name check: store
    set.clear();
    for (OcspServerConf.Store m : conf.getStores()) {
      String name = m.getName();
      if (set.contains(name)) {
        throw new InvalidConfException("duplicated definition of store named '" + name + "'");
      }
    }

    // Duplication name check: datasource
    set.clear();
    if (conf.getDatasources() != null) {
      for (DataSourceConf m : conf.getDatasources()) {
        String name = m.getName();
        if (set.contains(name)) {
          throw new InvalidConfException(
              "duplicated definition of datasource named '" + name + "'");
        }
        set.add(name);
      }
    }

    // assert that one directory will not be used duplicated by the source of type 'crl'
    Set<String> crlsDirs = new HashSet<>();
    for (OcspServerConf.Store m : conf.getStores()) {
      Source source = m.getSource();
      if ("crl".equalsIgnoreCase(source.getType())) {
        Object obj = source.getConf().get("dir");
        if (!(obj instanceof String)) {
          continue;
        }

        File file = new File((String) obj);
        String canonicalPath;
        try {
          canonicalPath = file.getCanonicalPath();
        } catch (IOException ex) {
          throw new InvalidConfException("error getCanonicalPath:" + ex.getMessage());
        }

        if (crlsDirs.contains(canonicalPath)) {
          throw new InvalidConfException(
              "duplicated use of dir '" + canonicalPath + "' in store " + m.getName());
        } else {
          crlsDirs.add(canonicalPath);
        }
      }
    }

    this.master = conf.isMaster();
    this.unknownIssuerBehaviour = conf.getUnknownIssuerBehaviour();
    if (this.unknownIssuerBehaviour == null) {
      this.unknownIssuerBehaviour = UnknownIssuerBehaviour.unknown;
    }

    // Response Cache
    OcspServerConf.ResponseCache cacheType = conf.getResponseCache();
    if (cacheType != null) {
      DataSourceConf cacheSourceConf = cacheType.getDatasource();
      DataSourceWrapper datasource;
      InputStream dsStream = null;
      try {
        dsStream = getInputStream(cacheSourceConf.getConf());
        datasource = datasourceFactory.createDataSource(cacheSourceConf.getName(),
                dsStream, securityFactory.getPasswordResolver());
      } catch (IOException ex) {
        throw new InvalidConfException(ex.getMessage(), ex);
      } finally {
        closeStream(dsStream);
      }
      responseCacher = new ResponseCacher(datasource, master, cacheType.validity());
      responseCacher.init();
    }

    //-- initializes the responders
    // signers
    for (OcspServerConf.Signer m : conf.getSigners()) {
      ResponseSigner signer = initSigner(m);
      signers.put(m.getName(), signer);
    }

    // requests
    for (OcspServerConf.RequestOption m : conf.getRequestOptions()) {
      RequestOption option = new RequestOption(m);
      requestOptions.put(m.getName(), option);
    }

    // responses
    for (OcspServerConf.ResponseOption m : conf.getResponseOptions()) {
      responseOptions.put(m.getName(), m);
    }

    // datasources
    Map<String, DataSourceWrapper> datasources = new HashMap<>();
    if (conf.getDatasources() != null) {
      for (DataSourceConf m : conf.getDatasources()) {
        String name = m.getName();
        DataSourceWrapper datasource;
        InputStream dsStream = null;
        try {
          dsStream = getInputStream(m.getConf());
          datasource = datasourceFactory.createDataSource(name,
                  dsStream, securityFactory.getPasswordResolver());
        } catch (IOException ex) {
          throw new InvalidConfException(ex.getMessage(), ex);
        } finally {
          closeStream(dsStream);
        }
        datasources.put(name, datasource);
      } // end for
    } // end if

    // responders
    Map<String, ResponderOption> responderOptions = new HashMap<>();

    for (OcspServerConf.Responder m : conf.getResponders()) {
      ResponderOption option = new ResponderOption(m);

      String optName = option.getSignerName();
      if (!signers.containsKey(optName)) {
        throw new InvalidConfException("no signer named '" + optName + "' is defined");
      }

      String reqOptName = option.getRequestOptionName();
      if (!requestOptions.containsKey(reqOptName)) {
        throw new InvalidConfException("no requestOption named '" + reqOptName + "' is defined");
      }

      String respOptName = option.getResponseOptionName();
      if (!responseOptions.containsKey(respOptName)) {
        throw new InvalidConfException("no responseOption named '" + respOptName + "' is defined");
      }

      // required HashAlgorithms for certificate
      List<OcspServerConf.Store> storeDefs = conf.getStores();
      Set<String> storeNames = new HashSet<>(storeDefs.size());
      for (OcspServerConf.Store storeDef : storeDefs) {
        storeNames.add(storeDef.getName());
      }

      responderOptions.put(m.getName(), option);
    } // end for

    // stores
    for (OcspServerConf.Store m : conf.getStores()) {
      OcspStore store = newStore(m, datasources);
      stores.put(m.getName(), store);
    }

    // responders
    for (String name : responderOptions.keySet()) {
      ResponderOption option = responderOptions.get(name);

      List<OcspStore> statusStores = new ArrayList<>(option.getStoreNames().size());
      for (String storeName : option.getStoreNames()) {
        statusStores.add(stores.get(storeName));
      }

      OcspServerConf.ResponseOption responseOption =
          responseOptions.get(option.getResponseOptionName());
      ResponseSigner signer = signers.get(option.getSignerName());
      if (signer.isMacSigner()) {
        if (responseOption.isResponderIdByName()) {
          throw new InvalidConfException(
              "could not use ResponderIdByName for signer " + option.getSignerName());
        }

        if (EmbedCertsMode.NONE != responseOption.getEmbedCertsMode()) {
          throw new InvalidConfException(
              "could not embed certifcate in response for signer " + option.getSignerName());
        }
      }

      ResponderImpl responder = new ResponderImpl(option,
          requestOptions.get(option.getRequestOptionName()),
          responseOption, signer, statusStores);
      responders.put(name, responder);
    } // end for

    // servlet paths
    List<SizeComparableString> tmpList = new LinkedList<>();
    for (String name : responderOptions.keySet()) {
      ResponderImpl responder = responders.get(name);
      ResponderOption option = responderOptions.get(name);
      List<String> strs = option.getServletPaths();
      for (String path : strs) {
        tmpList.add(new SizeComparableString(path));
        path2responderMap.put(path, responder);
      }
    }

    // Sort the servlet paths according to the length of path. The first one is the
    // longest, and the last one is the shortest.
    Collections.sort(tmpList);
    List<String> list2 = new ArrayList<>(tmpList.size());
    for (SizeComparableString m : tmpList) {
      list2.add(m.str);
    }
    this.servletPaths = list2;
  } // method init0

  @Override
  public void close() {
    LOG.info("stopped OCSP Responder");
    if (responseCacher != null) {
      responseCacher.close();
    }

    for (OcspStore store : stores.values()) {
      try {
        store.close();
      } catch (Exception ex) {
        LogUtil.warn(LOG, ex, "shutdown store " + store.getName());
      }
    }
  } // method close

  @Override
  public OcspRespWithCacheInfo answer(Responder responder2, byte[] request, boolean viaGet) {
    ResponderImpl responder = (ResponderImpl) responder2;
    RequestOption reqOpt = responder.getRequestOption();

    int version;
    try {
      version = OcspRequest.readRequestVersion(request);
    } catch (EncodingException ex) {
      String message = "could not extract version from request";
      LOG.warn(message);
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
    }

    if (!reqOpt.isVersionAllowed(version)) {
      String message = "invalid request version " + version;
      LOG.warn(message);
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
    }

    ResponseSigner signer = responder.getSigner();
    OcspServerConf.ResponseOption repOpt = responder.getResponseOption();

    try {
      Object reqOrRrrorResp = checkSignature(request, reqOpt);
      if (reqOrRrrorResp instanceof OcspRespWithCacheInfo) {
        return (OcspRespWithCacheInfo) reqOrRrrorResp;
      }

      OcspRequest req = (OcspRequest) reqOrRrrorResp;

      List<CertID> requestList = req.getRequestList();
      int requestsSize = requestList.size();
      if (requestsSize > reqOpt.getMaxRequestListCount()) {
        String message = requestsSize + " entries in RequestList, but maximal "
            + reqOpt.getMaxRequestListCount() + " is allowed";
        LOG.warn(message);
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
      }

      OcspRespControl repControl = new OcspRespControl();
      repControl.canCacheInfo = true;

      List<ExtendedExtension> reqExtensions = req.getExtensions();
      List<Extension> respExtensions = new LinkedList<>();

      ExtendedExtension ocspRespExtn = removeExtension(reqExtensions, OID.ID_PKIX_OCSP_RESPONSE);
      if (ocspRespExtn != null) {
        boolean containsBasic = ocspRespExtn.equalsExtnValue(encodedAcceptableResponses_Basic);
        if (!containsBasic) {
          // we need to parse the extension
          byte[] extnValue = new byte[ocspRespExtn.getExtnValueLength()];
          ocspRespExtn.writeExtnValue(extnValue, 0);
          ASN1Sequence seq = ASN1Sequence.getInstance(extnValue);
          final int size = seq.size();
          for (int i = 0; i < size; i++) {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(i));
            if (OCSPObjectIdentifiers.id_pkix_ocsp_basic.equals(oid)) {
              containsBasic = true;
              break;
            }
          }
        }

        if (!containsBasic) {
          LOG.warn("basic OCSP response is not accepted by the client");
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }
      }

      ExtendedExtension nonceExtn = removeExtension(reqExtensions, OID.ID_PKIX_OCSP_NONCE);
      if (nonceExtn != null) {
        if (reqOpt.getNonceOccurrence() == QuadrupleState.forbidden) {
          LOG.warn("nonce forbidden, but is present in the request");
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }

        if (reqOpt.getNonceOccurrence() == QuadrupleState.ignore) {
          nonceExtn = null;
        } else {
          int len = nonceExtn.getExtnValueLength();
          int min = reqOpt.getNonceMinLen();
          int max = reqOpt.getNonceMaxLen();

          if (len < min || len > max) {
            LOG.warn("length of nonce {} not within [{},{}]", len, min, max);
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
          }

          repControl.canCacheInfo = false;
          if (nonceExtn.isCritical()) {
            respExtensions.add(nonceExtn.revertCritical());
          } else {
            respExtensions.add(nonceExtn);
          }
        }
      } else {
        if (reqOpt.getNonceOccurrence() == QuadrupleState.required) {
          LOG.warn("nonce required, but is not present in the request");
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }
      }

      ConcurrentContentSigner concurrentSigner = null;
      if (responder.getResponderOption().getMode() != OcspMode.RFC2560) {
        ExtendedExtension extn = removeExtension(reqExtensions, OID.ID_PKIX_OCSP_PREFSIGALGS);
        if (extn != null) {
          ASN1InputStream asn1Stream = new ASN1InputStream(extn.getExtnValueStream());

          List<AlgorithmIdentifier> prefSigAlgs;
          try {
            ASN1Sequence seq = ASN1Sequence.getInstance(asn1Stream.readObject());
            final int size = seq.size();
            prefSigAlgs = new ArrayList<>(size);
            for (int i = 0; i < size; i++) {
              prefSigAlgs.add(AlgorithmIdentifier.getInstance(seq.getObjectAt(i)));
            }
          } finally {
            asn1Stream.close();
          }
          concurrentSigner = signer.getSignerForPreferredSigAlgs(prefSigAlgs);
        }
      }

      if (!reqExtensions.isEmpty()) {
        boolean flag = false;
        for (ExtendedExtension m : reqExtensions) {
          if (m.isCritical()) {
            flag = true;
            break;
          }
        }

        if (flag) {
          if (LOG.isWarnEnabled()) {
            List<OID> oids = new LinkedList<>();
            for (ExtendedExtension m : reqExtensions) {
              if (m.isCritical()) {
                oids.add(m.getExtnType());
              }
            }
            LOG.warn("could not process critial request extensions: {}", oids);
          }

          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }
      }

      if (concurrentSigner == null) {
        concurrentSigner = signer.getFirstSigner();
      }

      AlgorithmCode cacheDbSigAlgCode = null;
      BigInteger cacheDbSerialNumber = null;
      Integer cacheDbIssuerId = null;

      boolean canCacheDb = (requestsSize == 1) && (responseCacher != null)
          && (nonceExtn == null) && responseCacher.isOnService();
      if (canCacheDb) {
        // try to find the cached response
        CertID certId = requestList.get(0);
        HashAlgo reqHashAlgo = certId.getIssuer().hashAlgorithm();
        if (!reqOpt.allows(reqHashAlgo)) {
          LOG.warn("CertID.hashAlgorithm {} not allowed",
              reqHashAlgo != null ? reqHashAlgo : certId.getIssuer().hashAlgorithmOID());
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }

        cacheDbSigAlgCode = concurrentSigner.getAlgorithmCode();

        cacheDbIssuerId = responseCacher.getIssuerId(certId.getIssuer());
        cacheDbSerialNumber = certId.getSerialNumber();

        if (cacheDbIssuerId != null) {
          OcspRespWithCacheInfo cachedResp = responseCacher.getOcspResponse(
              cacheDbIssuerId.intValue(), cacheDbSerialNumber, cacheDbSigAlgCode);
          if (cachedResp != null) {
            return cachedResp;
          }
        } else if (master) {
          // store the issuer certificate in cache database.
          X509Cert issuerCert = null;
          for (OcspStore store : responder.getStores()) {
            issuerCert = store.getIssuerCert(certId.getIssuer());
            if (issuerCert != null) {
              break;
            }
          }

          if (issuerCert != null) {
            cacheDbIssuerId = responseCacher.storeIssuer(issuerCert);
          }
        }

        if (cacheDbIssuerId == null) {
          canCacheDb = false;
        }
      }

      ResponderID responderId = signer.getResponderId(repOpt.isResponderIdByName());
      OCSPRespBuilder builder = new OCSPRespBuilder(responderId);

      boolean unknownAsRevoked = false;
      AtomicBoolean unknownAsRevoked0 = new AtomicBoolean(false);
      for (int i = 0; i < requestsSize; i++) {
        OcspRespWithCacheInfo failureOcspResp = processCertReq(
            unknownAsRevoked0, requestList.get(i),
            builder, responder, reqOpt, repOpt, repControl);

        if (failureOcspResp != null) {
          return failureOcspResp;
        }

        if (unknownAsRevoked0.get()) {
          unknownAsRevoked = true;
        }
      }

      if (unknownAsRevoked && repControl.includeExtendedRevokeExtension) {
        respExtensions.add(extension_pkix_ocsp_extendedRevoke);
      }

      if (!respExtensions.isEmpty()) {
        builder.setResponseExtensions(new Extensions(respExtensions));
      }

      TaggedCertSequence certsInResp;
      EmbedCertsMode certsMode = repOpt.getEmbedCertsMode();
      if (certsMode == EmbedCertsMode.SIGNER) {
        certsInResp = signer.getSequenceOfCert();
      } else if (certsMode == EmbedCertsMode.NONE) {
        certsInResp = null;
      } else {
        // certsMode == EmbedCertsMode.SIGNER_AND_CA
        certsInResp = signer.getSequenceOfCertChain();
      }

      Date producedAt = new Date();
      byte[] encodeOcspResponse;
      try {
        encodeOcspResponse = builder.buildOCSPResponse(concurrentSigner, certsInResp, producedAt);
      } catch (NoIdleSignerException ex) {
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.tryLater);
      } catch (OCSPException ex) {
        LogUtil.error(LOG, ex, "answer() basicOcspBuilder.build");
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
      }

      long producedAtSeconds = producedAt.getTime() / 1000;
      // cache response in database
      if (canCacheDb && repControl.canCacheInfo) {
        // Don't cache the response with status UNKNOWN, since this may result in DDoS
        // of storage
        responseCacher.storeOcspResponse(cacheDbIssuerId.intValue(), cacheDbSerialNumber,
            producedAtSeconds, repControl.cacheNextUpdate, cacheDbSigAlgCode,
            encodeOcspResponse);
      }

      if (viaGet && repControl.canCacheInfo) {
        ResponseCacheInfo cacheInfo = new ResponseCacheInfo(producedAtSeconds);
        if (repControl.cacheNextUpdate != Long.MAX_VALUE) {
          cacheInfo.setNextUpdate(repControl.cacheNextUpdate);
        }
        return new OcspRespWithCacheInfo(encodeOcspResponse, cacheInfo);
      } else {
        return new OcspRespWithCacheInfo(encodeOcspResponse, null);
      }
    } catch (Throwable th) {
      LogUtil.error(LOG, th);
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
    }
  } // method ask

  private OcspRespWithCacheInfo processCertReq(AtomicBoolean unknownAsRevoked,
      CertID certId, OCSPRespBuilder builder,
      ResponderImpl responder, RequestOption reqOpt, OcspServerConf.ResponseOption repOpt,
      OcspRespControl repControl) throws IOException {
    HashAlgo reqHashAlgo = certId.getIssuer().hashAlgorithm();
    if (!reqOpt.allows(reqHashAlgo)) {
      LOG.warn("CertID.hashAlgorithm {} not allowed", reqHashAlgo);
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
    }

    CertStatusInfo certStatusInfo = null;
    boolean exceptionOccurs = false;

    BigInteger serial = certId.getSerialNumber();

    RequestIssuer reqIssuer = certId.getIssuer();
    Date now = new Date();
    for (OcspStore store : responder.getStores()) {
      if (!store.knowsIssuer(reqIssuer)) {
        continue;
      }

      try {
        certStatusInfo = store.getCertStatus(now, certId.getIssuer(), serial,
            repOpt.isIncludeCerthash(), repOpt.isIncludeInvalidityDate(),
            responder.getResponderOption().isInheritCaRevocation());
        if (certStatusInfo != null) {
          CertStatus status = certStatusInfo.getCertStatus();
          if (status == CertStatus.UNKNOWN || status == CertStatus.IGNORE) {
            switch (store.getUnknownCertBehaviour()) {
              case unknown:
                break;
              case good:
                if (status == CertStatus.UNKNOWN) {
                  certStatusInfo.setCertStatus(CertStatus.GOOD);
                }
                break;
              case malformedRequest:
                return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
              case internalError:
                return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
              case tryLater:
                return unsuccesfulOCSPRespMap.get(OcspResponseStatus.tryLater);
              default:
                break;
            }
          } else if (status == CertStatus.CRL_EXPIRED) {
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.tryLater);
          }

          exceptionOccurs = false;
          break;
        }
      } catch (OcspStoreException ex) {
        exceptionOccurs = true;
        LogUtil.error(LOG, ex, "getCertStatus() of CertStatusStore " + store.getName());
      }
    }

    if (exceptionOccurs) {
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.tryLater);
    }

    if (certStatusInfo == null) {
      switch (unknownIssuerBehaviour) {
        case unknown:
          final long msPerDay = 86400000L; // 24 * 60 * 60 * 1000L;
          Date nextUpdate = new Date(now.getTime() + msPerDay);
          certStatusInfo = CertStatusInfo.getIssuerUnknownCertStatusInfo(now, nextUpdate);
          break;
        case malformedRequest:
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        case unauthorized:
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
        case internalError:
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
        case tryLater:
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.tryLater);
        default:
          break;
      }
    }

    // certStatusInfo may not be null in any case, since at least one store is configured
    Date thisUpdate = certStatusInfo.getThisUpdate();
    if (thisUpdate == null) {
      thisUpdate = new Date();
    }

    Date nextUpdate = certStatusInfo.getNextUpdate();

    List<Extension> extensions = new LinkedList<>();
    unknownAsRevoked.set(false);
    byte[] certStatus;
    switch (certStatusInfo.getCertStatus()) {
      case GOOD:
        certStatus = bytes_certstatus_good;
        break;
      case ISSUER_UNKNOWN:
        repControl.canCacheInfo = false;
        certStatus = bytes_certstatus_unknown;
        break;
      case UNKNOWN:
      case IGNORE:
        repControl.canCacheInfo = false;
        if (responder.getResponderOption().getMode() == OcspMode.RFC2560) {
          certStatus = bytes_certstatus_unknown;
        } else { // (ocspMode == OCSPMode.RFC6960)
          unknownAsRevoked.set(true);
          certStatus = bytes_certstatus_rfc6960_unknown;
        }
        break;
      case REVOKED:
        CertRevocationInfo revInfo = certStatusInfo.getRevocationInfo();
        certStatus = Template.getEncodeRevokedInfo(
            repOpt.isIncludeRevReason() ? revInfo.getReason() : null, revInfo.getRevocationTime());

        Date invalidityDate = revInfo.getInvalidityTime();
        if (repOpt.isIncludeInvalidityDate() && invalidityDate != null
            && !invalidityDate.equals(revInfo.getRevocationTime())) {
          extensions.add(Template.getInvalidityDateExtension(invalidityDate));
        }
        break;
      default:
        throw new IllegalStateException(
            "unknown CertificateStatus:" + certStatusInfo.getCertStatus());
    } // end switch

    if (responder.getResponderOption().getMode() != OcspMode.RFC2560) {
      repControl.includeExtendedRevokeExtension = true;
    }

    byte[] certHash = certStatusInfo.getCertHash();
    if (certHash != null) {
      extensions.add(Template.getCertHashExtension(certStatusInfo.getCertHashAlgo(), certHash));
    }

    if (certStatusInfo.getArchiveCutOff() != null) {
      extensions.add(Template.getArchiveOffExtension(certStatusInfo.getArchiveCutOff()));
    }

    if (LOG.isDebugEnabled()) {
      String certStatusText = null;
      if (Arrays.equals(certStatus, bytes_certstatus_good)) {
        certStatusText = "good";
      } else if (Arrays.equals(certStatus, bytes_certstatus_unknown)) {
        certStatusText = "unknown";
      } else if (Arrays.equals(certStatus, bytes_certstatus_rfc6960_unknown)) {
        certStatusText = "RFC6960_unknown";
      } else  {
        certStatusText = unknownAsRevoked.get() ? "unknown_as_revoked" : "revoked";
      }

      String msg = StringUtil.concatObjectsCap(250, "issuer: ", certId.getIssuer(),
          ", serialNumber: ", LogUtil.formatCsn(certId.getSerialNumber()),
          ", certStatus: ", certStatusText, ", thisUpdate: ", thisUpdate,
          ", nextUpdate: ", nextUpdate);

      StringBuilder sb = new StringBuilder(msg.length() + 80);
      sb.append(msg);
      if (certHash != null) {
        sb.append(", certHash: ").append(Hex.encode(certHash));
      }
      LOG.debug(sb.toString());
    }

    if (CollectionUtil.isEmpty(extensions)) {
      builder.addResponse(certId, certStatus, thisUpdate, nextUpdate, null);
    } else {
      builder.addResponse(certId, certStatus, thisUpdate, nextUpdate, new Extensions(extensions));
    }

    if (nextUpdate != null) {
      repControl.cacheNextUpdate =
          Math.min(repControl.cacheNextUpdate, nextUpdate.getTime() / 1000);
    }

    return null;
  } // method processCertReq

  @Override
  public HealthCheckResult healthCheck(Responder responder2) {
    ResponderImpl responder = (ResponderImpl) responder2;
    HealthCheckResult result = new HealthCheckResult();
    result.setName("OCSPResponder");
    boolean healthy = true;

    for (OcspStore store : responder.getStores()) {
      boolean storeHealthy = store.isHealthy();
      healthy &= storeHealthy;

      HealthCheckResult storeHealth = new HealthCheckResult();
      storeHealth.setName("CertStatusStore." + store.getName());
      storeHealth.setHealthy(storeHealthy);
      result.addChildCheck(storeHealth);
    }

    boolean signerHealthy = responder.getSigner().isHealthy();
    healthy &= signerHealthy;

    HealthCheckResult signerHealth = new HealthCheckResult();
    signerHealth.setName("Signer");
    signerHealth.setHealthy(signerHealthy);
    result.addChildCheck(signerHealth);

    result.setHealthy(healthy);
    return result;
  } // method healthCheck

  public void refreshTokenForSignerType(String signerType) throws XiSecurityException {
    securityFactory.refreshTokenForSignerType(signerType);
  }

  private ResponseSigner initSigner(OcspServerConf.Signer signerType) throws InvalidConfException {
    X509Cert[] explicitCertificateChain = null;

    X509Cert explicitResponderCert = null;
    if (signerType.getCert() != null) {
      explicitResponderCert = parseCert(signerType.getCert());
    }

    if (explicitResponderCert != null) {
      Set<X509Cert> caCerts = null;
      if (signerType.getCaCerts() != null) {
        caCerts = new HashSet<>();

        for (FileOrBinary certConf : signerType.getCaCerts()) {
          caCerts.add(parseCert(certConf));
        }
      }

      try {
        explicitCertificateChain = X509Util.buildCertPath(explicitResponderCert, caCerts);
      } catch (CertPathBuilderException ex) {
        throw new InvalidConfException(ex);
      }
    }

    String responderSignerType = signerType.getType();
    String responderKeyConf = signerType.getKey();

    List<String> sigAlgos = signerType.getAlgorithms();
    List<ConcurrentContentSigner> singleSigners = new ArrayList<>(sigAlgos.size());
    for (String sigAlgo : sigAlgos) {
      try {
        ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
            responderSignerType, new SignerConf("algo=" + sigAlgo + "," + responderKeyConf),
            explicitCertificateChain);
        singleSigners.add(requestorSigner);
      } catch (ObjectCreationException ex) {
        throw new InvalidConfException(ex.getMessage(), ex);
      }
    }

    try {
      return new ResponseSigner(singleSigners);
    } catch (CertificateException | IOException ex) {
      throw new InvalidConfException(ex.getMessage(), ex);
    }
  } // method initSigner

  private OcspStore newStore(OcspServerConf.Store conf, Map<String, DataSourceWrapper> datasources)
      throws InvalidConfException {
    OcspStore store;
    try {
      String type = conf.getSource().getType();
      if (type != null) {
        type = type.trim();
      }

      if (StringUtil.isBlank(type)) {
        throw new ObjectCreationException("OCSP store type is not specified");
      } else if (STORE_TYPE_XIPKI_DB.equalsIgnoreCase(type)) {
        store = new DbCertStatusStore();
      } else if (STORE_TYPE_CRL.equalsIgnoreCase(type)) {
        store = new CrlDbCertStatusStore();
      } else if (STORE_TYPE_XIPKI_CA_DB.equalsIgnoreCase(type)) {
        store = new CaDbCertStatusStore();
      } else if (STORE_TYPE_EJBCA_DB.equalsIgnoreCase(type)) {
        store = new EjbcaCertStatusStore();
      } else if (type.startsWith("java:")) {
        String className = type.substring("java:".length()).trim();
        try {
          Class<?> clazz = Class.forName(className, false, getClass().getClassLoader());
          store = (OcspStore) clazz.newInstance();
        } catch (ClassNotFoundException | ClassCastException | InstantiationException
                | IllegalAccessException ex) {
          throw new InvalidConfException("ObjectCreationException of store " + conf.getName()
              + ":" + ex.getMessage(), ex);
        }
      } else {
        throw new ObjectCreationException("unknown OCSP store type " + type);
      }
    } catch (ObjectCreationException ex) {
      throw new InvalidConfException("ObjectCreationException of store " + conf.getName()
          + ":" + ex.getMessage(), ex);
    }

    store.setName(conf.getName());
    Integer interval = conf.getRetentionInterval();
    int retentionInterva = (interval == null) ? -1 : interval.intValue();
    store.setRetentionInterval(retentionInterva);
    store.setUnknownCertBehaviour(conf.getUnknownCertBehaviour());

    store.setIncludeArchiveCutoff(getBoolean(conf.getIncludeArchiveCutoff(), true));
    store.setIncludeCrlId(getBoolean(conf.getIncludeCrlId(), true));

    store.setIgnoreExpiredCert(getBoolean(conf.getIgnoreExpiredCert(), true));
    store.setIgnoreNotYetValidCert(getBoolean(conf.getIgnoreNotYetValidCert(), true));
    if (conf.getMinNextUpdatePeriod() != null) {
      store.setMinNextUpdatePeriod(Validity.getInstance(conf.getMinNextUpdatePeriod()));
    } else {
      store.setMinNextUpdatePeriod(null);
    }

    if ("NEVER".equalsIgnoreCase(conf.getUpdateInterval())) {
      store.setUpdateInterval(null);
    } else {
      String str = conf.getUpdateInterval();
      Validity updateInterval = Validity.getInstance(StringUtil.isBlank(str) ? "5m" : str);
      store.setUpdateInterval(updateInterval);
    }

    String datasourceName = conf.getSource().getDatasource();
    DataSourceWrapper datasource = null;
    if (datasourceName != null) {
      datasource = datasources.get(datasourceName);
      if (datasource == null) {
        throw new InvalidConfException("datasource named '" + datasourceName + "' not defined");
      }
    }
    try {
      Map<String, ? extends Object> sourceConf = conf.getSource().getConf();
      store.init(sourceConf, datasource);
    } catch (OcspStoreException ex) {
      throw new InvalidConfException("CertStatusStoreException of store " + conf.getName()
          + ":" + ex.getMessage(), ex);
    }

    return store;
  } // method newStore

  private Object checkSignature(byte[] request, RequestOption requestOption)
      throws OCSPException, CertificateParsingException, InvalidAlgorithmParameterException {
    OCSPRequest req;
    try {
      if (!requestOption.isValidateSignature()) {
        return OcspRequest.getInstance(request);
      }

      if (!OcspRequest.containsSignature(request)) {
        if (requestOption.isSignatureRequired()) {
          LOG.warn("signature in request required");
          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.sigRequired);
        } else {
          return OcspRequest.getInstance(request);
        }
      }

      try {
        req = OCSPRequest.getInstance(request);
      } catch (IllegalArgumentException ex) {
        throw new EncodingException("could not parse OCSP request", ex);
      }
    } catch (EncodingException ex) {
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
    }

    OCSPReq ocspReq = new OCSPReq(req);
    X509CertificateHolder[] bcCerts = ocspReq.getCerts();
    if (bcCerts == null || bcCerts.length < 1) {
      LOG.warn("no certificate found in request to verify the signature");
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
    }

    X509Cert[] certs = new X509Cert[bcCerts.length];
    for (int i = 0; i < certs.length; i++) {
      certs[i] = new X509Cert(bcCerts[i]);
    }

    ContentVerifierProvider cvp;
    try {
      cvp = securityFactory.getContentVerifierProvider(certs[0]);
    } catch (InvalidKeyException ex) {
      String message = ex.getMessage();
      LOG.warn("securityFactory.getContentVerifierProvider, InvalidKeyException: {}",
          message);
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
    }

    boolean sigValid = ocspReq.isSignatureValid(cvp);
    if (!sigValid) {
      LOG.warn("request signature is invalid");
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
    }

    // validate the certPath
    Date referenceTime = new Date();
    if (canBuildCertpath(certs, requestOption, referenceTime)) {
      try {
        return OcspRequest.getInstance(req);
      } catch (EncodingException ex) {
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
      }
    }

    LOG.warn("could not build certpath for the request's signer certificate");
    return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
  } // method checkSignature

  private static boolean canBuildCertpath(X509Cert[] certsInReq,
      RequestOption requestOption, Date referenceTime) {
    X509Cert target = certsInReq[0];

    Set<X509Cert> certstore = new HashSet<>();
    Set<X509Cert> trustAnchors = requestOption.getTrustAnchors();
    for (X509Cert m : trustAnchors) {
      certstore.add(m);
    }

    Set<X509Cert> configuredCerts = requestOption.getCerts();
    if (CollectionUtil.isNotEmpty(configuredCerts)) {
      certstore.addAll(requestOption.getCerts());
    }

    X509Cert[] certpath;
    try {
      certpath = X509Util.buildCertPath(target, certstore);
    } catch (CertPathBuilderException ex) {
      LogUtil.warn(LOG, ex);
      return false;
    }

    CertpathValidationModel model = requestOption.getCertpathValidationModel();

    Date now = new Date();
    if (model == null || model == CertpathValidationModel.PKIX) {
      for (X509Cert m : certpath) {
        if (m.getNotBefore().after(now) || m.getNotAfter().before(now)) {
          return false;
        }
      }
    } else if (model == CertpathValidationModel.CHAIN) {
      // do nothing
    } else {
      throw new IllegalStateException("invalid CertpathValidationModel " + model.name());
    }

    for (int i = certpath.length - 1; i >= 0; i--) {
      X509Cert targetCert = certpath[i];
      for (X509Cert m : trustAnchors) {
        if (m.equals(targetCert)) {
          return true;
        }
      }
    }

    return false;
  } // method canBuildCertpath

  private static boolean getBoolean(Boolean bo, boolean defaultValue) {
    return (bo == null) ? defaultValue : bo.booleanValue();
  }

  private static InputStream getInputStream(FileOrBinary conf) throws IOException {
    return (conf.getFile() != null)
        ? Files.newInputStream(Paths.get(IoUtil.expandFilepath(conf.getFile())))
        : new ByteArrayInputStream(conf.getBinary());
  }

  private static InputStream getInputStream(FileOrValue conf) throws IOException {
    return (conf.getFile() != null)
        ? Files.newInputStream(Paths.get(IoUtil.expandFilepath(conf.getFile())))
        : new ByteArrayInputStream(StringUtil.toUtf8Bytes(conf.getValue()));
  }

  private static void closeStream(InputStream stream) {
    if (stream == null) {
      return;
    }

    try {
      stream.close();
    } catch (IOException ex) {
      LOG.warn("could not close stream: {}", ex.getMessage());
    }
  }

  private static X509Cert parseCert(FileOrBinary certConf) throws InvalidConfException {
    InputStream is = null;
    try {
      is = getInputStream(certConf);
      return X509Util.parseCert(is);
    } catch (IOException | CertificateException ex) {
      String msg = "could not parse certificate";
      if (certConf.getFile() != null) {
        msg += " from file " + certConf.getFile();
      }
      throw new InvalidConfException(msg);
    } finally {
      closeStream(is);
    }
  } // method parseCert

  private static OcspServerConf parseConf(String confFilename) throws InvalidConfException {
    try (InputStream is = Files.newInputStream(
          Paths.get(IoUtil.expandFilepath(confFilename)))) {
      OcspServerConf root = JSON.parseObject(is, OcspServerConf.class);
      root.validate();
      return root;
    } catch (IOException | RuntimeException ex) {
      throw new InvalidConfException("parse profile failed, message: " + ex.getMessage(), ex);
    }
  } // method parseConf

  private static ExtendedExtension removeExtension(List<ExtendedExtension> extensions,
      OID extnType) {
    ExtendedExtension extn = null;
    for (ExtendedExtension m : extensions) {
      if (extnType == m.getExtnType()) {
        extn = m;
        break;
      }
    }

    if (extn != null) {
      extensions.remove(extn);
    }

    return extn;
  } // method removeExtension

}
