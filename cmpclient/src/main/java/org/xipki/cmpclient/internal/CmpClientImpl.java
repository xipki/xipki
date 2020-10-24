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

package org.xipki.cmpclient.internal;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.toNonBlankLower;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmpclient.CertIdOrError;
import org.xipki.cmpclient.CertprofileInfo;
import org.xipki.cmpclient.CmpClient;
import org.xipki.cmpclient.CmpClientException;
import org.xipki.cmpclient.EnrollCertRequest;
import org.xipki.cmpclient.EnrollCertResult;
import org.xipki.cmpclient.PkiErrorException;
import org.xipki.cmpclient.RevokeCertRequest;
import org.xipki.cmpclient.UnrevokeOrRemoveCertRequest;
import org.xipki.security.SecurityFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ReqRespDebug;

import com.alibaba.fastjson.JSON;

/**
 * Implementation of the interface {@link CmpClient}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public final class CmpClientImpl implements CmpClient {

  private static final Logger LOG = LoggerFactory.getLogger(CmpClientImpl.class);

  private CmpClientConfigurer configurer;

  public CmpClientImpl() {
    configurer = new CmpClientConfigurer();
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    configurer.setSecurityFactory(securityFactory);
  }

  public void setConfFile(String confFile) {
    configurer.setConfFile(confFile);
  }

  private void initIfNotInitialized()
      throws CmpClientException {
    configurer.initIfNotInitialized();
  }

  @Override
  public boolean init() {
    return configurer.init();
  }

  @Override
  public void close() {
    configurer.close();
  }

  @Override
  public EnrollCertResult enrollCert(String caName, CertificationRequest csr, String profile,
      Date notBefore, Date notAfter, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    notNull(csr, "csr");

    initIfNotInitialized();

    if (caName == null) {
      caName = getCaNameForProfile(profile);
    } else {
      caName = caName.toLowerCase();
    }

    if (caName == null) {
      throw new CmpClientException("certprofile " + profile + " is not supported by any CA");
    }

    CaConf ca = configurer.getCaConf(caName);
    if (ca == null) {
      throw new CmpClientException("could not find CA named " + caName);
    }

    final String id = "cert-1";
    CsrEnrollCertRequest request = new CsrEnrollCertRequest(id, profile, csr);
    EnrollCertResponse result = ca.getAgent().requestCertificate(
        request, notBefore, notAfter, debug);

    return parseEnrollCertResult(result);
  } // method enrollCert

  @Override
  public EnrollCertResult enrollCerts(String caName, EnrollCertRequest request,
      ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    List<EnrollCertRequest.Entry> requestEntries =
          notNull(request, "request").getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return null;
    }

    initIfNotInitialized();

    boolean bo = (caName != null);
    if (caName == null) {
      // detect the CA name
      String profile = requestEntries.get(0).getCertprofile();
      caName = getCaNameForProfile(profile);
      if (caName == null) {
        throw new CmpClientException("certprofile " + profile + " is not supported by any CA");
      }
    } else {
      caName = caName.toLowerCase();
    }

    if (bo || request.getRequestEntries().size() > 1) {
      // make sure that all requests are targeted on the same CA
      for (EnrollCertRequest.Entry entry : request.getRequestEntries()) {
        String profile = entry.getCertprofile();
        if (profile != null) {
          checkCertprofileSupportInCa(profile, caName);
        }
      }
    }

    CaConf ca = configurer.getCaConf(caName);
    if (ca == null) {
      throw new CmpClientException("could not find CA named " + caName);
    }

    EnrollCertResponse result = ca.getAgent().requestCertificate(request, debug);
    return parseEnrollCertResult(result);
  } // method enrollCerts

  private void checkCertprofileSupportInCa(String certprofile, String caName)
      throws CmpClientException {
    if (caName != null) {
      caName = caName.toLowerCase();
      CaConf ca = configurer.getCaConf(caName);
      if (ca == null) {
        throw new CmpClientException("unknown ca: " + caName);
      }

      if (!ca.supportsProfile(certprofile)) {
        throw new CmpClientException("certprofile " + certprofile + " is not supported by the CA "
            + caName);
      }
      return;
    }

    Map<String, CaConf> casMap = configurer.getCasMap();
    for (CaConf ca : casMap.values()) {
      if (!ca.isCaInfoConfigured()) {
        continue;
      }
      if (!ca.supportsProfile(certprofile)) {
        continue;
      }

      if (caName == null) {
        caName = ca.getName();
      } else {
        throw new CmpClientException("certprofile " + certprofile
            + " supported by more than one CA, please specify the CA name.");
      }
    }

    if (caName == null) {
      throw new CmpClientException("unsupported certprofile " + certprofile);
    }
  } // method checkCertprofileSupportInCa

  @Override
  public CertIdOrError revokeCert(String caName, X509Cert cert, int reason,
      Date invalidityDate, ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    notNull(cert, "cert");
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return revokeCert(ca, cert.getSerialNumber(), reason, invalidityDate, debug);
  } // method revokeCert

  @Override
  public CertIdOrError revokeCert(String caName, BigInteger serial, int reason, Date invalidityDate,
      ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    return revokeCert(ca, serial, reason, invalidityDate, debug);
  } // method revokeCert

  private CertIdOrError revokeCert(CaConf ca, BigInteger serial, int reason,
      Date invalidityDate, ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    notNull(ca, "ca");
    notNull(serial, "serial");

    final String id = "cert-1";
    RevokeCertRequest.Entry entry = new RevokeCertRequest.Entry(id, ca.getSubject(), serial, reason,
        invalidityDate);
    if (ca.getCmpControl().isRrAkiRequired()) {
      entry.setAuthorityKeyIdentifier(ca.getSubjectKeyIdentifier());
    }

    RevokeCertRequest request = new RevokeCertRequest();
    request.addRequestEntry(entry);
    Map<String, CertIdOrError> result = revokeCerts(request, debug);
    return (result == null) ? null : result.get(id);
  } // method revokeCert

  @Override
  public Map<String, CertIdOrError> revokeCerts(RevokeCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    List<RevokeCertRequest.Entry> requestEntries =
          notNull(request, "request").getRequestEntries();
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

    initIfNotInitialized();

    final String caName = getCaNameByIssuer(issuer);
    CaConf caConf = configurer.getCaConf(caName);
    if (caConf.getCmpControl().isRrAkiRequired()) {
      byte[] aki = caConf.getSubjectKeyIdentifier();
      List<RevokeCertRequest.Entry> entries = request.getRequestEntries();
      for (RevokeCertRequest.Entry entry : entries) {
        if (entry.getAuthorityKeyIdentifier() == null) {
          entry.setAuthorityKeyIdentifier(aki);
        }
      }
    }

    RevokeCertResponse result = caConf.getAgent().revokeCertificate(request, debug);
    return parseRevokeCertResult(result);
  } // method revokeCerts

  private Map<String, CertIdOrError> parseRevokeCertResult(RevokeCertResponse result)
      throws CmpClientException {
    Map<String, CertIdOrError> ret = new HashMap<>();

    for (ResultEntry re : result.getResultEntries()) {
      CertIdOrError certIdOrError;
      if (re instanceof ResultEntry.RevokeCert) {
        ResultEntry.RevokeCert entry = (ResultEntry.RevokeCert) re;
        certIdOrError = new CertIdOrError(entry.getCertId());
      } else if (re instanceof ResultEntry.Error) {
        ResultEntry.Error entry = (ResultEntry.Error) re;
        certIdOrError = new CertIdOrError(entry.getStatusInfo());
      } else {
        throw new CmpClientException("unknown type " + re.getClass().getName());
      }

      ret.put(re.getId(), certIdOrError);
    }

    return ret;
  } // method parseRevokeCertResult

  @Override
  public X509CRLHolder downloadCrl(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    caName = toNonBlankLower(caName, "caName");
    return downloadCrl(caName, (BigInteger) null, debug);
  } // method downloadCrl

  @Override
  public X509CRLHolder downloadCrl(String caName, BigInteger crlNumber, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    caName = toNonBlankLower(caName, "caName");
    initIfNotInitialized();

    CaConf ca = configurer.getCaConf(caName);
    if (ca == null) {
      throw new IllegalArgumentException("unknown CA " + caName);
    }

    CmpAgent agent = ca.getAgent();
    X509CRLHolder result = (crlNumber == null) ? agent.downloadCurrentCrl(debug)
          : agent.downloadCrl(crlNumber, debug);

    return result;
  } // method downloadCrl

  @Override
  public X509CRLHolder generateCrl(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    caName = toNonBlankLower(caName, "caName");

    initIfNotInitialized();

    CaConf ca = configurer.getCaConf(caName);
    if (ca == null) {
      throw new IllegalArgumentException("unknown CA " + caName);
    }

    return ca.getAgent().generateCrl(debug);
  } // method generateCrl

  @Override
  public String getCaNameByIssuer(X500Name issuer)
      throws CmpClientException {
    notNull(issuer, "issuer");

    initIfNotInitialized();

    Map<String, CaConf> casMap = configurer.getCasMap();
    for (String name : casMap.keySet()) {
      final CaConf ca = casMap.get(name);
      if (!ca.isCaInfoConfigured()) {
        continue;
      }

      if (CompareUtil.equalsObject(ca.getSubject(), issuer)) {
        return name;
      }
    }

    throw new CmpClientException("unknown CA for issuer: " + issuer);
  } // method getCaNameByIssuer

  @Override
  public String getCaNameForProfile(String certprofile)
      throws CmpClientException {
    String caName = null;
    Map<String, CaConf> casMap = configurer.getCasMap();
    for (CaConf ca : casMap.values()) {
      if (!ca.isCaInfoConfigured()) {
        continue;
      }

      if (!ca.supportsProfile(certprofile)) {
        continue;
      }

      if (caName == null) {
        caName = ca.getName();
      } else {
        throw new CmpClientException("certprofile " + certprofile
                + " supported by more than one CA, please specify the CA name.");
      }
    }

    return caName;
  } // method getCaNameForProfile

  private X509Cert getCertificate(CMPCertificate cmpCert)
      throws CertificateException {
    Certificate bcCert = cmpCert.getX509v3PKCert();
    return (bcCert == null) ? null : new X509Cert(bcCert);
  }

  @Override
  public Set<String> getCaNames()
      throws CmpClientException {
    initIfNotInitialized();
    return configurer.getCasMap().keySet();
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
    } catch (SignatureException | InvalidKeyException | CertificateException
        | NoSuchAlgorithmException | NoSuchProviderException ex) {
      LOG.debug("{} while verifying signature: {}", ex.getClass().getName(), ex.getMessage());
      return false;
    }
  } // method verify

  @Override
  public CertIdOrError unrevokeCert(String caName, X509Cert cert, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    notNull(cert, "cert");
    initIfNotInitialized();

    CaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return unrevokeCert(ca, cert.getSerialNumber(), debug);
  } // method unrevokeCert

  @Override
  public CertIdOrError unrevokeCert(String caName, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    return unrevokeCert(ca, serial, debug);
  }

  private CertIdOrError unrevokeCert(CaConf ca, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    notNull(ca, "ca");
    notNull(serial, "serial");
    final String id = "cert-1";
    ResultEntry.UnrevokeOrRemoveCert entry = new ResultEntry.UnrevokeOrRemoveCert(
        id, ca.getSubject(), serial);
    if (ca.getCmpControl().isRrAkiRequired()) {
      entry.setAuthorityKeyIdentifier(ca.getSubjectKeyIdentifier());
    }

    UnrevokeOrRemoveCertRequest request = new UnrevokeOrRemoveCertRequest();
    UnrevokeOrRemoveCertRequest.Entry entry2 = new UnrevokeOrRemoveCertRequest.Entry(
        entry.getId(), entry.getIssuer(), entry.getSerialNumber());
    entry2.setAuthorityKeyIdentifier(entry.getAuthorityKeyIdentifier());
    request.addRequestEntry(entry2);
    Map<String, CertIdOrError> result = unrevokeCerts(request, debug);
    return (result == null) ? null : result.get(id);
  } // method unrevokeCert

  @Override
  public Map<String, CertIdOrError> unrevokeCerts(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    notNull(request, "request");

    initIfNotInitialized();
    List<UnrevokeOrRemoveCertRequest.Entry> requestEntries = request.getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return Collections.emptyMap();
    }

    X500Name issuer = requestEntries.get(0).getIssuer();
    for (int i = 1; i < requestEntries.size(); i++) {
      if (!issuer.equals(requestEntries.get(i).getIssuer())) {
        throw new PkiErrorException(PKIStatus.REJECTION, PKIFailureInfo.badRequest,
            "unrevoking certificates issued by more than one CA is not allowed");
      }
    }

    final String caName = getCaNameByIssuer(issuer);
    CmpAgent agent = configurer.getCaConf(caName).getAgent();
    RevokeCertResponse result = agent.unrevokeCertificate(request, debug);
    return parseRevokeCertResult(result);
  } // method unrevokeCerts

  @Override
  public CertIdOrError removeCert(String caName, X509Cert cert, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    notNull(cert, "cert");
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return removeCert(ca, cert.getSerialNumber(), debug);
  } // method removeCert

  @Override
  public CertIdOrError removeCert(String caName, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    return removeCert(ca, serial, debug);
  } // method removeCert

  private CertIdOrError removeCert(CaConf ca, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    notNull(ca, "ca");
    notNull(serial, "serial");
    final String id = "cert-1";
    UnrevokeOrRemoveCertRequest.Entry entry =
        new UnrevokeOrRemoveCertRequest.Entry(id, ca.getSubject(), serial);
    if (ca.getCmpControl().isRrAkiRequired()) {
      entry.setAuthorityKeyIdentifier(ca.getSubjectKeyIdentifier());
    }

    UnrevokeOrRemoveCertRequest request = new UnrevokeOrRemoveCertRequest();
    request.addRequestEntry(entry);
    Map<String, CertIdOrError> result = removeCerts(request, debug);
    return (result == null) ? null : result.get(id);
  } // method removeCert

  @Override
  public Map<String, CertIdOrError> removeCerts(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    notNull(request, "request");

    initIfNotInitialized();
    List<UnrevokeOrRemoveCertRequest.Entry> requestEntries = request.getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return Collections.emptyMap();
    }

    X500Name issuer = requestEntries.get(0).getIssuer();
    for (int i = 1; i < requestEntries.size(); i++) {
      if (!issuer.equals(requestEntries.get(i).getIssuer())) {
        throw new PkiErrorException(PKIStatus.REJECTION, PKIFailureInfo.badRequest,
            "removing certificates issued by more than one CA is not allowed");
      }
    }

    final String caName = getCaNameByIssuer(issuer);
    CmpAgent agent = configurer.getCaConf(caName).getAgent();
    RevokeCertResponse result = agent.removeCertificate(request, debug);
    return parseRevokeCertResult(result);
  } // method removeCerts

  @Override
  public Set<CertprofileInfo> getCertprofiles(String caName)
      throws CmpClientException {
    caName = toNonBlankLower(caName, "caName");

    initIfNotInitialized();
    CaConf ca = configurer.getCaConf(caName);
    if (ca == null) {
      return Collections.emptySet();
    }

    Set<String> profileNames = ca.getProfileNames();
    if (CollectionUtil.isEmpty(profileNames)) {
      return Collections.emptySet();
    }

    Set<CertprofileInfo> ret = new HashSet<>(profileNames.size());
    for (String m : profileNames) {
      ret.add(ca.getProfile(m));
    }
    return ret;
  } // method getCertprofiles

  @Override
  public HealthCheckResult getHealthCheckResult(String caName)
      throws CmpClientException {
    caName = toNonBlankLower(caName, "caName");

    String name = "X509CA";
    HealthCheckResult healthCheckResult = new HealthCheckResult();
    healthCheckResult.setName(name);

    try {
      initIfNotInitialized();
    } catch (CmpClientException ex) {
      LogUtil.error(LOG, ex, "could not initialize CaCleint");
      healthCheckResult.setHealthy(false);
      return healthCheckResult;
    }

    CaConf ca = configurer.getCaConf(caName);
    if (ca == null) {
      throw new IllegalArgumentException("unknown CA " + caName);
    }

    String healthUrlStr = ca.getHealthUrl();

    URL serverUrl;
    try {
      serverUrl = new URL(healthUrlStr);
    } catch (MalformedURLException ex) {
      throw new CmpClientException("invalid URL '" + healthUrlStr + "'");
    }

    try {
      HttpURLConnection httpUrlConnection = IoUtil.openHttpConn(serverUrl);
      if (httpUrlConnection instanceof HttpsURLConnection) {
        if (ca.getHostnameVerifier() != null) {
          ((HttpsURLConnection) httpUrlConnection).setHostnameVerifier(ca.getHostnameVerifier());
        }
        if (ca.getSslSocketFactory() != null) {
          ((HttpsURLConnection) httpUrlConnection).setSSLSocketFactory(ca.getSslSocketFactory());
        }
      }

      InputStream inputStream = httpUrlConnection.getInputStream();
      int responseCode = httpUrlConnection.getResponseCode();
      if (responseCode != HttpURLConnection.HTTP_OK
          && responseCode != HttpURLConnection.HTTP_INTERNAL_ERROR) {
        inputStream.close();
        throw new IOException(String.format("bad response: code='%s', message='%s'",
            httpUrlConnection.getResponseCode(), httpUrlConnection.getResponseMessage()));
      }

      String responseContentType = httpUrlConnection.getContentType();
      boolean isValidContentType = false;
      if (responseContentType != null) {
        if ("application/json".equalsIgnoreCase(responseContentType)) {
          isValidContentType = true;
        }
      }

      if (!isValidContentType) {
        inputStream.close();
        throw new IOException("bad response: mime type " + responseContentType + " not supported!");
      }

      byte[] responseBytes = IoUtil.read(inputStream);
      if (responseBytes.length == 0) {
        healthCheckResult.setHealthy(responseCode == HttpURLConnection.HTTP_OK);
      } else {
        try {
          healthCheckResult = JSON.parseObject(responseBytes, HealthCheckResult.class);
        } catch (RuntimeException ex) {
          LogUtil.error(LOG, ex, "IOException while parsing the health json message");
          if (LOG.isDebugEnabled()) {
            LOG.debug("json message: {}", new String(responseBytes));
          }
          healthCheckResult.setHealthy(false);
        }
      }
    } catch (IOException ex) {
      LogUtil.error(LOG, ex, "IOException while fetching the URL " + healthUrlStr);
      healthCheckResult.setHealthy(false);
    }

    return healthCheckResult;
  } // method getHealthCheckResult

  private EnrollCertResult parseEnrollCertResult(EnrollCertResponse result)
      throws CmpClientException {
    Map<String, EnrollCertResult.CertifiedKeyPairOrError> certOrErrors = new HashMap<>();
    for (ResultEntry resultEntry : result.getResultEntries()) {
      EnrollCertResult.CertifiedKeyPairOrError certOrError;
      if (resultEntry instanceof ResultEntry.EnrollCert) {
        ResultEntry.EnrollCert entry = (ResultEntry.EnrollCert) resultEntry;
        try {
          X509Cert cert = getCertificate(entry.getCert());
          certOrError =
              new EnrollCertResult.CertifiedKeyPairOrError(cert, entry.getPrivateKeyInfo());
        } catch (CertificateException ex) {
          throw new CmpClientException(String.format(
              "CertificateParsingException for request (id=%s): %s",
              entry.getId(), ex.getMessage()));
        }
      } else if (resultEntry instanceof ResultEntry.Error) {
        certOrError =
            new EnrollCertResult.CertifiedKeyPairOrError(
                  ((ResultEntry.Error) resultEntry).getStatusInfo());
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
      try {
        caPubs.add(getCertificate(cmpCaPub));
      } catch (CertificateException ex) {
        LogUtil.error(LOG, ex, "could not extract the caPub from CMPCertificate");
      }
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

    return new EnrollCertResult(caCert, certOrErrors);
  } // method parseEnrollCertResult

  private CaConf getCa(String caName)
      throws CmpClientException {
    Map<String, CaConf> casMap = configurer.getCasMap();
    if (caName == null) {
      Iterator<String> names = casMap.keySet().iterator();
      if (!names.hasNext()) {
        throw new CmpClientException("no CA is configured");
      }
      caName = names.next();
    } else {
      caName = caName.toLowerCase();
    }

    CaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new CmpClientException("could not find CA named " + caName);
    }
    return ca;
  } // method parse

  private static void assertIssuedByCa(X509Cert cert, CaConf ca)
      throws CmpClientException {
    boolean issued;
    try {
      issued = X509Util.issues(ca.getCert(), cert);
    } catch (CertificateEncodingException ex) {
      LogUtil.error(LOG, ex);
      issued = false;
    }
    if (!issued) {
      throw new CmpClientException("the given certificate is not issued by the CA");
    }
  } // method assertIssuedByCa

  @Override
  public X509Cert getCaCert(String caName)
      throws CmpClientException {
    initIfNotInitialized();

    CaConf ca = configurer.getCaConf(caName);
    return ca == null ? null : ca.getCert();
  }

  @Override
  public List<X509Cert> getCaCertchain(String caName)
      throws CmpClientException {
    initIfNotInitialized();

    CaConf ca = configurer.getCaConf(caName);
    return ca == null ? null : ca.getCertchain();
  }

  @Override
  public X500Name getCaCertSubject(String caName)
      throws CmpClientException {
    initIfNotInitialized();
    CaConf ca = configurer.getCaConf(caName);
    return ca == null ? null : ca.getSubject();
  }

  @Override
  public List<X509Cert> getDhPocPeerCertificates(String caName)
      throws CmpClientException {
    initIfNotInitialized();
    CaConf ca = configurer.getCaConf(caName);
    return ca == null ? null : ca.getDhpocs();
  }

}
