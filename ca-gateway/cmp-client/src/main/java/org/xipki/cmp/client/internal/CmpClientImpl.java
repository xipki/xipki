// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmp.client.*;
import org.xipki.security.CollectionAlgorithmValidator;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.SslContextConf;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Implementation of the interface {@link CmpClient}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public final class CmpClientImpl implements CmpClient {

  private static final Logger LOG = LoggerFactory.getLogger(CmpClientImpl.class);

  private SecurityFactory securityFactory;

  private CmpAgent agent;

  private List<X509Cert> dhpopCerts;

  private String confFile;

  private final AtomicBoolean initialized = new AtomicBoolean(false);

  public CmpClientImpl() {
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  public void setConfFile(String confFile) {
    this.confFile = confFile;
  }

  public void init() throws Exception {
    if (this.initialized.get()) {
      return;
    }

    if (confFile == null) {
      throw new IllegalStateException("confFile is not set");
    }

    if (securityFactory == null) {
      throw new IllegalStateException("securityFactory is not set");
    }

    // reset
    this.initialized.set(false);

    LOG.info("initializing ...");
    File configFile = new File(IoUtil.expandFilepath(confFile));
    if (!configFile.exists()) {
      throw new IllegalStateException("could not find configuration file " + confFile);
    }

    CmpClientConf conf = parse(configFile);
    SslContextConf sslCc = SslContextConf.ofSslConf(conf.getSsl());

    SSLSocketFactory sslSocketFactory = sslCc.getSslSocketFactory();
    HostnameVerifier hostnameVerifier = sslCc.getHostnameVerifier();

    // Responder configuration
    CmpClientConf.Responder responderConf = conf.getResponder();
    String serverUrl = responderConf.getUrl();

    Responder signatureResponder = null;
    CmpClientConf.Responder.Signature sigResponderConf = responderConf.getSignature();
    if (sigResponderConf != null) {
      X509Cert cert = X509Util.parseCert(sigResponderConf.getCert().readContent());

      Set<String> algoNames = new HashSet<>(sigResponderConf.getSignatureAlgos());

      Set<SignAlgo> algos = new HashSet<>();
      for (String algoName : algoNames) {
        SignAlgo sa = SignAlgo.getInstance(algoName);
        algos.add(sa);
      }

      if (algos.isEmpty()) {
        throw new NoSuchAlgorithmException("none of the signature algorithms " + algoNames + " are supported");
      }

      signatureResponder = new Responder.SignatureCmpResponder(cert, new CollectionAlgorithmValidator(algos));
    }

    Responder pbmMacResponder = null;
    CmpClientConf.Responder.PbmMac pbmMacResponderConf = responderConf.getPbmMac();
    if (pbmMacResponderConf != null) {
      pbmMacResponder = new Responder.PbmMacCmpResponder(pbmMacResponderConf.getOwfAlgos(),
          pbmMacResponderConf.getMacAlgos());
    }

    if (responderConf.getDhPopCerts() != null) {
      this.dhpopCerts = X509Util.parseCerts(responderConf.getDhPopCerts().readContent());
    }

    this.agent = new CmpAgent(signatureResponder, pbmMacResponder, serverUrl, securityFactory,
        sslSocketFactory, hostnameVerifier, conf.isSendRequestorCert());

    initialized.set(true);
    LOG.info("initialized");
  } // method init

  private static CmpClientConf parse(File configFile) throws CmpClientException {
    CmpClientConf conf;
    try {
      conf = JSON.parseObject(configFile, CmpClientConf.class);
      conf.validate();
    } catch (InvalidConfException | IOException | RuntimeException ex) {
      throw new CmpClientException("parsing profile failed, message: " + ex.getMessage(), ex);
    }

    return conf;
  }

  @Override
  public void close() {
  }

  @Override
  public EnrollCertResult enrollCert(
      String caName, Requestor requestor, CertificationRequest csr, String profile,
      Instant notBefore, Instant notAfter, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Args.notNull(csr, "csr");
    caName = Args.notBlank(caName, "caName").toLowerCase(Locale.ROOT);

    final String id = "cert-1";
    CsrEnrollCertRequest request = new CsrEnrollCertRequest(id, profile, csr);
    EnrollCertResponse result = agent.requestCertificate(caName, requestor, request, notBefore, notAfter, debug);

    return parseEnrollCertResult(result);
  }

  @Override
  public EnrollCertResult enrollCerts(
      String caName, Requestor requestor, EnrollCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    caName = Args.notBlank(caName, "caName").toLowerCase(Locale.ROOT);
    List<EnrollCertRequest.Entry> requestEntries = Args.notNull(request, "request").getRequestEntries();
    return CollectionUtil.isEmpty(requestEntries) ? null
        : parseEnrollCertResult(agent.requestCertificate(caName, requestor, request, debug));
  }

  @Override
  public CertIdOrError revokeCert(
      String caName, Requestor requestor, X509Cert issuerCert, X509Cert cert,
      int reason, Instant invalidityDate, ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    Args.notNull(cert, "cert");
    assertIssuedByCa(cert, issuerCert);
    return revokeCert(caName, requestor, issuerCert, cert.getSerialNumber(), reason, invalidityDate, debug);
  }

  @Override
  public CertIdOrError revokeCert(
      String caName, Requestor requestor, X509Cert issuerCert, BigInteger serial,
      int reason, Instant invalidityDate, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Args.notNull(caName, "caName");
    Args.notNull(serial, "serial");

    final String id = "cert-1";
    RevokeCertRequest.Entry entry = new RevokeCertRequest.Entry(
        id, issuerCert.getSubject(), serial, reason, invalidityDate);
    entry.setAuthorityKeyIdentifier(issuerCert.getSubjectKeyId());

    RevokeCertRequest request = new RevokeCertRequest();
    request.addRequestEntry(entry);
    Map<String, CertIdOrError> result = revokeCerts(caName, requestor, request, debug);
    return (result == null) ? null : result.get(id);
  }

  @Override
  public Map<String, CertIdOrError> revokeCerts(
      String caName, Requestor requestor, RevokeCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    List<RevokeCertRequest.Entry> requestEntries = Args.notNull(request, "request").getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return Collections.emptyMap();
    }

    X500Name issuer = requestEntries.get(0).getIssuer();
    for (int i = 1; i < requestEntries.size(); i++) {
      if (!issuer.equals(requestEntries.get(i).getIssuer())) {
        throw new PkiErrorException(PKIStatus.REJECTION, PKIFailureInfo.badRequest,
            "revoking certificates issued by more than one CA is not allowed");
      }
    }

    return parseRevokeCertResult(agent.revokeCertificate(caName, requestor, request, debug));
  }

  private Map<String, CertIdOrError> parseRevokeCertResult(RevokeCertResponse result) throws CmpClientException {
    Map<String, CertIdOrError> ret = new HashMap<>();

    for (ResultEntry re : result.getResultEntries()) {
      CertIdOrError certIdOrError;
      if (re instanceof ResultEntry.RevokeCert) {
        certIdOrError = new CertIdOrError(((ResultEntry.RevokeCert) re).getCertId());
      } else if (re instanceof ResultEntry.Error) {
        certIdOrError = new CertIdOrError(((ResultEntry.Error) re).getStatusInfo());
      } else {
        throw new CmpClientException("unknown type " + re.getClass().getName());
      }

      ret.put(re.getId(), certIdOrError);
    }

    return ret;
  }

  @Override
  public X509CRLHolder downloadCrl(String caName, ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    return agent.downloadCurrentCrl(Args.toNonBlankLower(caName, "caName"), debug);
  }

  private static X509Cert getCertificate(CMPCertificate cmpCert) {
    Certificate bcCert = cmpCert.getX509v3PKCert();
    return (bcCert == null) ? null : new X509Cert(bcCert);
  }

  private static boolean verify(X509Cert caCert, X509Cert cert) {
    if (!cert.getIssuer().equals(caCert.getSubject())) {
      return false;
    }

    boolean inBenchmark = Boolean.getBoolean("org.xipki.benchmark");
    if (inBenchmark) {
      return true;
    }

    PublicKey caPublicKey = caCert.getPublicKey();
    try {
      cert.verify(caPublicKey);
      return true;
    } catch (GeneralSecurityException ex) {
      LOG.debug("{} while verifying signature: {}", ex.getClass().getName(), ex.getMessage());
      return false;
    }
  }

  @Override
  public CertIdOrError unsuspendCert(
      String caName, Requestor requestor, X509Cert issuerCert, X509Cert cert, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    assertIssuedByCa(Args.notNull(cert, "cert"), issuerCert);
    return unsuspendCert(caName, requestor, issuerCert, cert.getSerialNumber(), debug);
  }

  @Override
  public CertIdOrError unsuspendCert(
      String caName, Requestor requestor, X509Cert issuerCert, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    final String id = "cert-1";

    ResultEntry.UnrevokeOrRemoveCert entry = new ResultEntry.UnrevokeOrRemoveCert(id,
        Args.notNull(issuerCert, "issuerCert").getSubject(),
        Args.notNull(serial, "serial"));
    entry.setAuthorityKeyIdentifier(issuerCert.getSubjectKeyId());

    UnrevokeCertRequest request = new UnrevokeCertRequest();
    UnrevokeCertRequest.Entry entry2 = new UnrevokeCertRequest.Entry(
        entry.getId(), entry.getIssuer(), entry.getSerialNumber());
    entry2.setAuthorityKeyIdentifier(entry.getAuthorityKeyIdentifier());
    request.addRequestEntry(entry2);
    Map<String, CertIdOrError> result = unsuspendCerts(caName, requestor, request, debug);
    return (result == null) ? null : result.get(id);
  }

  @Override
  public Map<String, CertIdOrError> unsuspendCerts(
      String caName, Requestor requestor, UnrevokeCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    List<UnrevokeCertRequest.Entry> requestEntries = Args.notNull(request, "request").getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return Collections.emptyMap();
    }

    X500Name issuer = requestEntries.get(0).getIssuer();
    for (int i = 1; i < requestEntries.size(); i++) {
      if (!issuer.equals(requestEntries.get(i).getIssuer())) {
        throw new PkiErrorException(PKIStatus.REJECTION, PKIFailureInfo.badRequest,
            "unsuspending certificates issued by more than one CA is not allowed");
      }
    }

    return parseRevokeCertResult(agent.unrevokeCertificate(caName, requestor, request, debug));
  }

  private EnrollCertResult parseEnrollCertResult(EnrollCertResponse result) {
    Map<String, EnrollCertResult.CertifiedKeyPairOrError> certOrErrors = new HashMap<>();
    for (ResultEntry resultEntry : result.getResultEntries()) {
      EnrollCertResult.CertifiedKeyPairOrError certOrError;
      if (resultEntry instanceof ResultEntry.EnrollCert) {
        ResultEntry.EnrollCert entry = (ResultEntry.EnrollCert) resultEntry;
        X509Cert cert = getCertificate(entry.getCert());
        certOrError = new EnrollCertResult.CertifiedKeyPairOrError(cert, entry.getPrivateKeyInfo());
      } else if (resultEntry instanceof ResultEntry.Error) {
        certOrError = new EnrollCertResult.CertifiedKeyPairOrError(((ResultEntry.Error) resultEntry).getStatusInfo());
      } else {
        certOrError = null;
      }

      certOrErrors.put(resultEntry.getId(), certOrError);
    }

    List<CMPCertificate> cmpCaPubs = result.getCaCertificates();

    if (CollectionUtil.isEmpty(cmpCaPubs)) {
      return new EnrollCertResult(null, certOrErrors);
    }

    List<X509Cert> caPubs = new ArrayList<>(cmpCaPubs.size());
    for (CMPCertificate cmpCaPub : cmpCaPubs) {
      caPubs.add(getCertificate(cmpCaPub));
    }

    X509Cert caCert = null;
    for (EnrollCertResult.CertifiedKeyPairOrError certOrError : certOrErrors.values()) {
      X509Cert cert = certOrError.getCertificate();
      if (cert == null) {
        continue;
      }

      for (X509Cert caPub : caPubs) {
        if (verify(caPub, cert)) {
          caCert = caPub;
          break;
        }
      }

      if (caCert != null) {
        break;
      }
    }

    if (caCert == null) {
      return new EnrollCertResult(null, certOrErrors);
    }

    for (EnrollCertResult.CertifiedKeyPairOrError certOrError : certOrErrors.values()) {
      X509Cert cert = certOrError.getCertificate();
      if (cert == null) {
        continue;
      }

      if (!verify(caCert, cert)) {
        LOG.warn("not all certificates are issued by CA embedded in caPubs, ignore the caPubs");
        return new EnrollCertResult(null, certOrErrors);
      }
    }

    // find further certificates
    caPubs.remove(caCert);
    X509Cert[] caCertChain = caPubs.isEmpty() ? new X509Cert[]{caCert}
        : X509Util.buildCertPath(caCert, caPubs, true);

    return new EnrollCertResult(caCertChain, certOrErrors);
  } // method parseEnrollCertResult

  private static void assertIssuedByCa(X509Cert cert, X509Cert ca) throws CmpClientException {
    boolean issued = X509Util.issues(ca, cert);
    if (!issued) {
      throw new CmpClientException("the given certificate is not issued by the CA");
    }
  }

  @Override
  public X509Cert caCert(String caName, ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    return agent.caCerts(caName, 1, debug).get(0);
  }

  @Override
  public List<X509Cert> caCerts(String caName, ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    return agent.caCerts(caName, 99, debug);
  }

  @Override
  public List<X509Cert> getDhPopPeerCertificates() {
    return dhpopCerts == null ? Collections.emptyList() : Collections.unmodifiableList(dhpopCerts);
  }

}
