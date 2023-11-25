// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

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
import org.xipki.datasource.DataSourceConf;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.license.api.OcspLicense;
import org.xipki.ocsp.api.*;
import org.xipki.ocsp.api.CertStatusInfo.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo.UnknownIssuerBehaviour;
import org.xipki.ocsp.api.OcspRespWithCacheInfo.ResponseCacheInfo;
import org.xipki.ocsp.server.OcspServerConf.EmbedCertsMode;
import org.xipki.ocsp.server.OcspServerConf.Source;
import org.xipki.ocsp.server.ResponderOption.OcspMode;
import org.xipki.ocsp.server.store.IssuerEntry;
import org.xipki.ocsp.server.store.ResponseCacher;
import org.xipki.ocsp.server.type.*;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.*;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.xipki.ocsp.server.OcspServerUtil.*;

/**
 * Implementation of {@link OcspServer}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OcspServerImpl implements OcspServer {

  private static class OcspRespControl {
    boolean canCacheInfo;
    boolean includeExtendedRevokeExtension;
    long cacheNextUpdate;

    public OcspRespControl() {
      includeExtendedRevokeExtension = false;
      cacheNextUpdate = Long.MAX_VALUE;
    }
  } // class OcspRespControl

  private static final byte[] DERNullBytes = new byte[]{0x05, 0x00};

  private static final byte[] bytes_certstatus_good = new byte[]{(byte) 0x80, 0x00};

  private static final byte[] bytes_certstatus_unknown = new byte[]{(byte) 0x82, 0x00};

  private static final byte[] bytes_certstatus_rfc6960_unknown =
      Hex.decode("a116180f31393730303130313030303030305aa0030a0106");

  private static final WritableOnlyExtension extension_pkix_ocsp_extendedRevoke;

  private static final Logger LOG = LoggerFactory.getLogger(OcspServerImpl.class);

  private static final Map<OcspResponseStatus, OcspRespWithCacheInfo> unsuccesfulOCSPRespMap;

  private static final byte[] encodedAcceptableResponses_Basic;

  private final DataSourceFactory datasourceFactory;

  private SecurityFactory securityFactory;

  private String confFile;

  private boolean master;

  private final OcspLicense license;

  private UnknownIssuerBehaviour unknownIssuerBehaviour = UnknownIssuerBehaviour.unknown;

  private ResponseCacher responseCacher;

  private final Map<String, ResponderImpl> responders = new HashMap<>();

  private final Map<String, ResponseSigner> signers = new HashMap<>();

  private final Map<String, RequestOption> requestOptions = new HashMap<>();

  private final Map<String, OcspServerConf.ResponseOption> responseOptions = new HashMap<>();

  private final Map<String, OcspStore> stores = new HashMap<>();

  private final List<String> servletPaths = new ArrayList<>();

  private final Map<String, ResponderImpl> path2responderMap = new HashMap<>();

  private final AtomicBoolean initialized = new AtomicBoolean(false);

  static {
    LOG.info("XiPKI OCSP Responder version {}", StringUtil.getBundleVersion(OcspServerImpl.class));

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

    ExtendedExtension ext = new ExtendedExtension(OID.ID_PKIX_OCSP_EXTENDEDREVOKE, false, DERNullBytes);
    byte[] encoded = new byte[ext.getEncodedLength()];
    ext.write(encoded, 0);
    extension_pkix_ocsp_extendedRevoke = new WritableOnlyExtension(encoded);

    encodedAcceptableResponses_Basic = Hex.decode("300B06092B0601050507300101");
  } // method static

  public OcspServerImpl(OcspLicense license) {
    this.datasourceFactory = new DataSourceFactory();
    this.license = Args.notNull(license, "license");
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  public void setConfFile(String confFile) {
    this.confFile = confFile;
  }

  @Override
  public ResponderAndPath getResponderForPath(String path) {
    for (String servletPath : servletPaths) {
      if (path.startsWith(servletPath)) {
        return new ResponderAndPath(servletPath, path2responderMap.get(servletPath));
      }
    }
    return null;
  }

  public ResponderImpl getResponder(String name) {
    return responders.get(Args.notBlank(name, "name"));
  }

  public boolean isInitialized() {
    return initialized.get();
  }

  public void init(boolean force) throws OcspStoreException, InvalidConfException, PasswordResolverException {
    LOG.info("starting OCSPResponder server ...");
    if (initialized.get()) {
      if (!force) {
        LOG.info("already started, skipping ...");
        return;
      }
    }

    init0();
    initialized.set(true);
    LOG.info("started OCSPResponder server");
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
    for (Entry<String, OcspStore> entry : stores.entrySet()) {
      OcspStore store = entry.getValue();
      try {
        store.close();
      } catch (IOException ex) {
        throw new OcspStoreException("could not close OCSP store " + entry.getKey(), ex);
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

      if (StringUtil.orEqualsIgnoreCase(name, "health", "mgmt")) {
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
            || (ch >= 'a' && ch <= 'z') || ch == '-' || ch == '_' || ch == '.')) {
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
        throw new InvalidConfException("duplicated definition of signer option named '" + name + "'");
      }
      set.add(name);
    }

    // Duplication name check: requests
    set.clear();
    for (OcspServerConf.RequestOption m : conf.getRequestOptions()) {
      String name = m.getName();
      if (set.contains(name)) {
        throw new InvalidConfException("duplicated definition of request option named '" + name + "'");
      }
      set.add(name);
    }

    // Duplication name check: response
    set.clear();
    for (OcspServerConf.ResponseOption m : conf.getResponseOptions()) {
      String name = m.getName();
      if (set.contains(name)) {
        throw new InvalidConfException("duplicated definition of response option named '" + name + "'");
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
      set.add(name);
    }

    // Duplication name check: datasource
    set.clear();
    if (conf.getDatasources() != null) {
      for (DataSourceConf m : conf.getDatasources()) {
        String name = m.getName();
        if (set.contains(name)) {
          throw new InvalidConfException("duplicated definition of datasource named '" + name + "'");
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
          throw new InvalidConfException("duplicated use of dir '" + canonicalPath + "' in store " + m.getName());
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
      try (InputStream dsStream = getInputStream(cacheSourceConf.getConf())) {
        datasource = datasourceFactory.createDataSource(cacheSourceConf.getName(),
                dsStream, securityFactory.getPasswordResolver());
      } catch (IOException ex) {
        throw new InvalidConfException(ex.getMessage(), ex);
      }
      responseCacher = new ResponseCacher(datasource, master, cacheType.validity());
      responseCacher.init();
    }

    //-- initializes the responders
    // signers
    for (OcspServerConf.Signer m : conf.getSigners()) {
      signers.put(m.getName(), initSigner(m, securityFactory));
    }

    // requests
    for (OcspServerConf.RequestOption m : conf.getRequestOptions()) {
      requestOptions.put(m.getName(), new RequestOption(m));
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
        try (InputStream dsStream = getInputStream(m.getConf())) {
          datasource = datasourceFactory.createDataSource(name, dsStream, securityFactory.getPasswordResolver());
        } catch (IOException ex) {
          throw new InvalidConfException(ex.getMessage(), ex);
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

      responderOptions.put(m.getName(), option);
    } // end for

    // stores
    for (OcspServerConf.Store m : conf.getStores()) {
      OcspStore store = newStore(m, datasources);
      stores.put(m.getName(), store);
    }

    // responders
    for (Entry<String, ResponderOption> entry : responderOptions.entrySet()) {
      String name = entry.getKey();
      ResponderOption option = entry.getValue();

      List<OcspStore> statusStores = new ArrayList<>(option.getStoreNames().size());
      for (String storeName : option.getStoreNames()) {
        statusStores.add(stores.get(storeName));
      }

      OcspServerConf.ResponseOption responseOption = responseOptions.get(option.getResponseOptionName());
      ResponseSigner signer = signers.get(option.getSignerName());
      if (signer.isMacSigner()) {
        if (responseOption.isResponderIdByName()) {
          throw new InvalidConfException("could not use ResponderIdByName for signer " + option.getSignerName());
        }

        if (EmbedCertsMode.NONE != responseOption.getEmbedCertsMode()) {
          throw new InvalidConfException("could not embed certifcate in response for signer " + option.getSignerName());
        }
      }

      ResponderImpl responder = new ResponderImpl(option, requestOptions.get(option.getRequestOptionName()),
              responseOption, signer, statusStores);
      responders.put(name, responder);
    } // end for

    // servlet paths
    List<String> tmpList = new LinkedList<>();
    for (Entry<String, ResponderOption> entry : responderOptions.entrySet()) {
      String name = entry.getKey();
      ResponderImpl responder = responders.get(name);
      ResponderOption option = entry.getValue();
      List<String> strs = option.getServletPaths();
      for (String path : strs) {
        tmpList.add(path);
        path2responderMap.put(path, responder);
      }
    }

    // Sort the servlet paths according to the length of path. The first one is the
    // longest, and the last one is the shortest.
    tmpList.sort((o1, o2) -> o2.length() - o1.length());
    this.servletPaths.clear();
    this.servletPaths.addAll(tmpList);
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
      Object reqOrErrorResp = checkSignature(request, reqOpt);
      if (reqOrErrorResp instanceof OcspRespWithCacheInfo) {
        // error
        return (OcspRespWithCacheInfo) reqOrErrorResp;
      }

      OcspRequest req = (OcspRequest) reqOrErrorResp;

      List<CertID> requestList = req.getRequestList();
      int requestsSize = requestList.size();
      if (requestsSize > reqOpt.getMaxRequestListCount()) {
        String message = requestsSize + " entries in RequestList, but maximal "
            + reqOpt.getMaxRequestListCount() + " is allowed";
        LOG.warn(message);
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
      }

      //-----begin license -----
      if (!license.isValid()) {
        LOG.error("License not valid, need new license");
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
      }

      if (!license.grantAllCAs()) {
        for (CertID cid : requestList) {
          for (OcspStore store : responder.getStores()) {
            X509Cert caCert = store.getIssuerCert(cid.getIssuer());
            if (caCert == null) {
              continue;
            }

            String issuerSubject = caCert.getSubjectText();
            boolean granted = license.grant(issuerSubject);
            if (!granted) {
              LOG.error("Not granted for CA {}, need new license", issuerSubject);
              return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
            }
          }
        }
      }

      license.regulateSpeed();
      //-----end license-----

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
          List<AlgorithmIdentifier> prefSigAlgs;
          try (ASN1InputStream asn1Stream = new ASN1InputStream(extn.getExtnValueStream())) {
            ASN1Sequence seq = ASN1Sequence.getInstance(asn1Stream.readObject());
            final int size = seq.size();
            prefSigAlgs = new ArrayList<>(size);
            for (int i = 0; i < size; i++) {
              prefSigAlgs.add(AlgorithmIdentifier.getInstance(seq.getObjectAt(i)));
            }
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
            LOG.warn("could not process critical request extensions: {}", oids);
          }

          return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }
      }

      if (concurrentSigner == null) {
        concurrentSigner = signer.getFirstSigner();
      }

      SignAlgo cacheDbSigAlg = null;
      BigInteger cacheDbSerialNumber = null;
      IssuerEntry cacheDbIssuer = null;

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

        cacheDbSigAlg = concurrentSigner.getAlgorithm();

        cacheDbIssuer = responseCacher.getIssuer(certId.getIssuer());
        cacheDbSerialNumber = certId.getSerialNumber();

        if (cacheDbIssuer != null) {
          OcspRespWithCacheInfo cachedResp = responseCacher.getOcspResponse(
              cacheDbIssuer.getId(), cacheDbSerialNumber, cacheDbSigAlg);
          if (cachedResp != null) {
            if (license.grant(cacheDbIssuer.getCert().getSubjectText())) {
              return cachedResp;
            } else {
              LOG.error("Not granted, new license needed");
              return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
            }
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
            cacheDbIssuer = responseCacher.storeIssuer(issuerCert);
          }
        }

        if (cacheDbIssuer == null) {
          canCacheDb = false;
        }
      }

      ResponderID responderId = signer.getResponderId(repOpt.isResponderIdByName());
      OCSPRespBuilder builder = new OCSPRespBuilder(responderId);

      boolean unknownAsRevoked = false;
      AtomicBoolean unknownAsRevoked0 = new AtomicBoolean(false);
      for (CertID certID : requestList) {
        OcspRespWithCacheInfo failureOcspResp = processCertReq(
                unknownAsRevoked0, certID, builder, responder, reqOpt, repOpt, repControl);

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

      EmbedCertsMode certsMode = repOpt.getEmbedCertsMode();
      TaggedCertSequence certsInResp = (certsMode == EmbedCertsMode.SIGNER) ? signer.getSequenceOfCert()
          : (certsMode == EmbedCertsMode.NONE) ? null
          : signer.getSequenceOfCertChain(); // certsMode == EmbedCertsMode.SIGNER_AND_CA

      Instant producedAt = Instant.now();
      byte[] encodeOcspResponse;
      try {
        encodeOcspResponse = builder.buildOCSPResponse(concurrentSigner, certsInResp, producedAt);
      } catch (NoIdleSignerException ex) {
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.tryLater);
      } catch (OCSPException ex) {
        LogUtil.error(LOG, ex, "answer() basicOcspBuilder.build");
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
      }

      long producedAtSeconds = producedAt.getEpochSecond();
      // cache response in database
      if (canCacheDb && repControl.canCacheInfo) {
        // Don't cache the response with status UNKNOWN, since this may result in DDoS
        // of storage
        responseCacher.storeOcspResponse(cacheDbIssuer.getId(), cacheDbSerialNumber,
            producedAtSeconds, repControl.cacheNextUpdate, cacheDbSigAlg, encodeOcspResponse);
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

  private OcspRespWithCacheInfo processCertReq(
      AtomicBoolean unknownAsRevoked, CertID certId, OCSPRespBuilder builder, ResponderImpl responder,
      RequestOption reqOpt, OcspServerConf.ResponseOption repOpt, OcspRespControl repControl) {
    HashAlgo reqHashAlgo = certId.getIssuer().hashAlgorithm();
    if (!reqOpt.allows(reqHashAlgo)) {
      LOG.warn("CertID.hashAlgorithm {} not allowed", reqHashAlgo);
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
    }

    CertStatusInfo certStatusInfo = null;
    boolean exceptionOccurs = false;

    BigInteger serial = certId.getSerialNumber();

    RequestIssuer reqIssuer = certId.getIssuer();
    Instant now = Instant.now();
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
              case unknown:
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
      LOG.info("issuer unknown, return {}", unknownIssuerBehaviour);
      switch (unknownIssuerBehaviour) {
        case unknown:
          Instant nextUpdate = Instant.now().plus(1, ChronoUnit.DAYS);
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
          throw new IllegalStateException("unreachable code");
      }
    }

    // certStatusInfo may not be null in any case, since at least one store is configured
    Instant thisUpdate = certStatusInfo.getThisUpdate();
    if (thisUpdate == null) {
      thisUpdate = Instant.now();
    }

    Instant nextUpdate = certStatusInfo.getNextUpdate();

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

        Instant invalidityDate = revInfo.getInvalidityTime();
        if (repOpt.isIncludeInvalidityDate() && invalidityDate != null
            && !invalidityDate.equals(revInfo.getRevocationTime())) {
          extensions.add(Template.getInvalidityDateExtension(invalidityDate));
        }
        break;
      default:
        throw new IllegalStateException("unknown CertificateStatus:" + certStatusInfo.getCertStatus());
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
      String certStatusText = Arrays.equals(certStatus, bytes_certstatus_good) ? "good"
          : Arrays.equals(certStatus, bytes_certstatus_unknown) ? "unknown"
          : Arrays.equals(certStatus, bytes_certstatus_rfc6960_unknown) ? "RFC6960_unknown"
          : unknownAsRevoked.get() ? "unknown_as_revoked"
          : "revoked";

      String msg = StringUtil.concatObjectsCap(250, "issuer: ", certId.getIssuer(),
          ", serialNumber: ", LogUtil.formatCsn(certId.getSerialNumber()),
          ", certStatus: ", certStatusText, ", thisUpdate: ", thisUpdate,
          ", nextUpdate: ", nextUpdate);
      if (certHash == null) {
        LOG.debug(msg);
      } else {
        LOG.debug(msg + ", certHash: " + Hex.encode(certHash));
      }
    }

    if (CollectionUtil.isEmpty(extensions)) {
      builder.addResponse(certId, certStatus, thisUpdate, nextUpdate, null);
    } else {
      builder.addResponse(certId, certStatus, thisUpdate, nextUpdate, new Extensions(extensions));
    }

    if (nextUpdate != null) {
      repControl.cacheNextUpdate = Math.min(repControl.cacheNextUpdate, nextUpdate.getEpochSecond());
    }

    return null;
  } // method processCertReq

  @Override
  public boolean healthCheck(Responder responder2) {
    ResponderImpl responder = (ResponderImpl) responder2;

    for (OcspStore store : responder.getStores()) {
      boolean storeHealthy = store.isHealthy();
      if (!storeHealthy) {
        return false;
      }
    }

    return responder.getSigner().isHealthy();
  } // method healthCheck

  private Object checkSignature(byte[] request, RequestOption requestOption)
      throws OCSPException {
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
      LOG.warn("securityFactory.getContentVerifierProvider, InvalidKeyException: {}", message);
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
    }

    if (!ocspReq.isSignatureValid(cvp)) {
      LOG.warn("request signature is invalid");
      return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
    }

    // validate the certPath
    Instant referenceTime = Instant.now();
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

  private static InputStream getInputStream(FileOrValue conf) throws IOException {
    return (conf.getFile() != null)
        ? Files.newInputStream(Paths.get(IoUtil.expandFilepath(conf.getFile(), true)))
        : new ByteArrayInputStream(StringUtil.toUtf8Bytes(conf.getValue()));
  }

}
