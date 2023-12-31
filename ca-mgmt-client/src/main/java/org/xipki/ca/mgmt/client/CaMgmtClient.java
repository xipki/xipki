// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.client;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaJson;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.MgmtAction;
import org.xipki.ca.api.mgmt.MgmtRequest;
import org.xipki.ca.api.mgmt.MgmtResponse;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.KeyCertBytesPair;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.SslContextConf;
import org.xipki.util.http.SslContextConfWrapper;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CA management client via REST API.
 *
 * @author Lijun Liao (xipki)
 */

public class CaMgmtClient implements CaManager {

  private static final Logger LOG = LoggerFactory.getLogger(CaMgmtClient.class);

  private static final String REQUEST_CT = "application/json";

  private static final String RESPONSE_CT = "application/json";

  private final Map<MgmtAction, URL> actionUrlMap = new HashMap<>(50);

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private final SslContextConf sslContextConf;

  private boolean initialized;

  private CaMgmtException initException;

  static {
    LOG.info("XiPKI CA Management Client version {}", StringUtil.getBundleVersion(CaMgmtClient.class));
  }

  public CaMgmtClient(SslContextConfWrapper sslContextConfWrapper) throws ObjectCreationException {
    this.sslContextConf = sslContextConfWrapper == null ? null : sslContextConfWrapper.toSslContextConf();
    if (this.sslContextConf != null) {
      this.sslContextConf.init();
    }
  }

  public synchronized void initIfNotDone() throws CaMgmtException {
    if (initException != null) {
      throw initException;
    }

    if (initialized) {
      return;
    }

    try {
      if (sslContextConf != null) {
        sslSocketFactory = sslContextConf.getSslSocketFactory();
        hostnameVerifier = sslContextConf.getHostnameVerifier();
      }
    } catch (Exception ex) {
      initException = new CaMgmtException("could not initialize CaMgmtClient: " + ex.getMessage(), ex);
      throw initException;
    } finally {
      initialized = true;
    }
  } // method initIfNotDone

  public void setServerUrl(String serverUrl) throws MalformedURLException {
    Args.notBlank(serverUrl, "serverUrl");
    if (!serverUrl.endsWith("/") ) {
      serverUrl += "/";
    }

    for (MgmtAction action : MgmtAction.values()) {
      actionUrlMap.put(action, new URL(serverUrl + action));
    }
  }

  @Override
  public CaSystemStatus getCaSystemStatus() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getCaSystemStatus, null);
    return parse(respBytes, MgmtResponse.GetCaSystemStatus.class).getResult();
  }

  @Override
  public void unlockCa() throws CaMgmtException {
    voidTransmit(MgmtAction.unlockCa, null);
  }

  @Override
  public void notifyCaChange() throws CaMgmtException {
    voidTransmit(MgmtAction.notifyCaChange, null);
  }

  @Override
  public void addDbSchema(String name, String value) throws CaMgmtException {
    MgmtRequest.AddOrChangeDbSchema req = new MgmtRequest.AddOrChangeDbSchema();
    req.setName(name);
    req.setValue(value);
    voidTransmit(MgmtAction.addDbSchema, req);
  }

  @Override
  public void changeDbSchema(String name, String value) throws CaMgmtException {
    MgmtRequest.AddOrChangeDbSchema req = new MgmtRequest.AddOrChangeDbSchema();
    req.setName(name);
    req.setValue(value);
    voidTransmit(MgmtAction.changeDbSchema, req);
  }

  public void removeDbSchema(String name) throws CaMgmtException {
    removeEntity(MgmtAction.removeDbSchema, name);
  }

  @Override
  public Map<String, String> getDbSchemas() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getDbSchemas, null);
    return parse(respBytes, MgmtResponse.GetDbSchemas.class).getResult();
  }

  @Override
  public void republishCertificates(String caName, List<String> publisherNames, int numThreads)
      throws CaMgmtException {
    MgmtRequest.RepublishCertificates req = new MgmtRequest.RepublishCertificates();
    req.setCaName(caName);
    req.setPublisherNames(publisherNames);
    req.setNumThreads(numThreads);
    voidTransmit(MgmtAction.republishCertificates, req);
  }

  @Override
  public void removeCa(String caName) throws CaMgmtException {
    removeEntity(MgmtAction.removeCa, caName);
  }

  @Override
  public void restartCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    voidTransmit(MgmtAction.restartCa, req);
  }

  @Override
  public void restartCaSystem() throws CaMgmtException {
    voidTransmit(MgmtAction.restartCaSystem, null);
  }

  @Override
  public void addCaAlias(String aliasName, String caName) throws CaMgmtException {
    MgmtRequest.AddCaAlias req = new MgmtRequest.AddCaAlias();
    req.setAliasName(aliasName);
    req.setCaName(caName);
    voidTransmit(MgmtAction.addCaAlias, req);
  }

  @Override
  public void removeCaAlias(String aliasName) throws CaMgmtException {
    removeEntity(MgmtAction.removeCaAlias, aliasName);
  }

  @Override
  public Set<String> getAliasesForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getAliasesForCa, req);
    return parse(respBytes, MgmtResponse.StringSet.class).getResult();
  }

  @Override
  public String getCaNameForAlias(String aliasName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(aliasName);
    byte[] respBytes = transmit(MgmtAction.getCaNameForAlias, req);
    return parse(respBytes, MgmtResponse.StringResponse.class).getResult();
  }

  @Override
  public Set<String> getCaAliasNames() throws CaMgmtException {
    return getNames(MgmtAction.getCaAliasNames);
  }

  @Override
  public Set<String> getCertprofileNames() throws CaMgmtException {
    return getNames(MgmtAction.getCertprofileNames);
  }

  @Override
  public Set<String> getKeypairGenNames() throws CaMgmtException {
    return getNames(MgmtAction.getKeypairGenNames);
  }

  @Override
  public Set<String> getPublisherNames() throws CaMgmtException {
    return getNames(MgmtAction.getPublisherNames);
  }

  @Override
  public Set<String> getRequestorNames() throws CaMgmtException {
    return getNames(MgmtAction.getRequestorNames);
  }

  @Override
  public Set<String> getSignerNames() throws CaMgmtException {
    return getNames(MgmtAction.getSignerNames);
  }

  @Override
  public Set<String> getCaNames() throws CaMgmtException {
    return getNames(MgmtAction.getCaNames);
  }

  @Override
  public Set<String> getSuccessfulCaNames() throws CaMgmtException {
    return getNames(MgmtAction.getSuccessfulCaNames);
  }

  @Override
  public Set<String> getFailedCaNames() throws CaMgmtException {
    return getNames(MgmtAction.getFailedCaNames);
  }

  @Override
  public Set<String> getInactiveCaNames() throws CaMgmtException {
    return getNames(MgmtAction.getInactiveCaNames);
  }

  private Set<String> getNames(MgmtAction action) throws CaMgmtException {
    byte[] respBytes = transmit(action, null);
    return parse(respBytes, MgmtResponse.StringSet.class).getResult();
  }

  @Override
  public void addCa(CaEntry caEntry) throws CaMgmtException {
    MgmtRequest.AddCa req = new MgmtRequest.AddCa();
    req.setCaEntry(caEntry);
    voidTransmit(MgmtAction.addCa, req);
  }

  @Override
  public List<X509Cert> getCaCerts(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getCaCerts, req);
    try {
      String str = parse(respBytes, MgmtResponse.StringResponse.class).getResult();
      return X509Util.parseCerts(str.getBytes(StandardCharsets.UTF_8));
    } catch (IOException | CertificateException ex) {
      throw new CaMgmtException(ex);
    }
  }

  @Override
  public CaEntry getCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getCa, req);
    MgmtResponse.GetCa resp = parse(respBytes, MgmtResponse.GetCa.class);
    return resp.getResult();
  }

  @Override
  public void changeCa(ChangeCaEntry changeCaEntry) throws CaMgmtException {
    MgmtRequest.ChangeCa req = new MgmtRequest.ChangeCa();
    req.setChangeCaEntry(changeCaEntry);
    voidTransmit(MgmtAction.changeCa, req);
  }

  @Override
  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setEntityName(profileName);
    req.setCaName(caName);
    voidTransmit(MgmtAction.removeCertprofileFromCa, req);
  }

  @Override
  public void addCertprofileToCa(String profileNameAndAliases, String caName) throws CaMgmtException {
    MgmtRequest.AddCertprofileToCa req = new MgmtRequest.AddCertprofileToCa();
    req.setProfileName(profileNameAndAliases);
    req.setCaName(caName);
    voidTransmit(MgmtAction.addCertprofileToCa, req);
  }

  @Override
  public void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setCaName(caName);
    req.setEntityName(publisherName);
    voidTransmit(MgmtAction.removePublisherFromCa, req);
  }

  @Override
  public void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    MgmtRequest.AddPublisherToCa req = new MgmtRequest.AddPublisherToCa();
    req.setPublisherName(publisherName);
    req.setCaName(caName);
    voidTransmit(MgmtAction.addPublisherToCa, req);
  }

  @Override
  public Set<CaProfileEntry> getCertprofilesForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getCertprofilesForCa, req);
    Set<String> list = parse(respBytes, MgmtResponse.StringSet.class).getResult();
    if (list == null) {
      return Collections.emptySet();
    }

    Set<CaProfileEntry> ret = new HashSet<>();
    for (String m : list) {
      ret.add(CaProfileEntry.decode(m));
    }
    return ret;
  }

  @Override
  public Set<CaHasRequestorEntry> getRequestorsForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getRequestorsForCa, req);
    return parse(respBytes, MgmtResponse.GetRequestorsForCa.class).getResult();
  }

  @Override
  public RequestorEntry getRequestor(String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    byte[] respBytes = transmit(MgmtAction.getRequestor, req);
    return parse(respBytes, MgmtResponse.GetRequestor.class).getResult();
  }

  @Override
  public void addRequestor(RequestorEntry requestorEntry) throws CaMgmtException {
    MgmtRequest.AddRequestor req = new MgmtRequest.AddRequestor();
    req.setRequestorEntry(requestorEntry);
    voidTransmit(MgmtAction.addRequestor, req);
  }

  @Override
  public void removeRequestor(String requestorName) throws CaMgmtException {
    removeEntity(MgmtAction.removeRequestor, requestorName);
  }

  @Override
  public void changeRequestor(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(MgmtAction.changeRequestor, req);
  }

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setCaName(caName);
    req.setEntityName(requestorName);
    voidTransmit(MgmtAction.removeRequestorFromCa, req);
  }

  @Override
  public void addRequestorToCa(CaHasRequestorEntry requestor, String caName) throws CaMgmtException {
    MgmtRequest.AddRequestorToCa req = new MgmtRequest.AddRequestorToCa();
    req.setRequestor(requestor);
    req.setCaName(caName);
    voidTransmit(MgmtAction.addRequestorToCa, req);
  }

  @Override
  public KeypairGenEntry getKeypairGen(String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    byte[] respBytes = transmit(MgmtAction.getKeypairGen, req);
    return parse(respBytes, MgmtResponse.GetKeypairGen.class).getResult();
  }

  @Override
  public void removeKeypairGen(String name) throws CaMgmtException {
    removeEntity(MgmtAction.removeKeypairGen, name);
  }

  @Override
  public void changeKeypairGen(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(MgmtAction.changeKeypairGen, req);
  }

  @Override
  public void addKeypairGen(KeypairGenEntry keypairGenEntry) throws CaMgmtException {
    MgmtRequest.AddKeypairGen req = new MgmtRequest.AddKeypairGen();
    req.setEntry(keypairGenEntry);
    voidTransmit(MgmtAction.addKeypairGen, req);
  }

  @Override
  public CertprofileEntry getCertprofile(String profileName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(profileName);
    byte[] respBytes = transmit(MgmtAction.getCertprofile, req);
    return parse(respBytes, MgmtResponse.GetCertprofile.class).getResult();
  }

  @Override
  public void removeCertprofile(String profileName) throws CaMgmtException {
    removeEntity(MgmtAction.removeCertprofile, profileName);
  }

  @Override
  public void changeCertprofile(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(MgmtAction.changeCertprofile, req);
  }

  @Override
  public void addCertprofile(CertprofileEntry certprofileEntry) throws CaMgmtException {
    MgmtRequest.AddCertprofile req = new MgmtRequest.AddCertprofile();
    req.setCertprofileEntry(certprofileEntry);
    voidTransmit(MgmtAction.addCertprofile, req);
  }

  @Override
  public void addSigner(SignerEntry signerEntry) throws CaMgmtException {
    MgmtRequest.AddSigner req = new MgmtRequest.AddSigner();
    req.setSignerEntry(signerEntry);
    voidTransmit(MgmtAction.addSigner, req);
  }

  @Override
  public void removeSigner(String name) throws CaMgmtException {
    removeEntity(MgmtAction.removeSigner, name);
  }

  @Override
  public SignerEntry getSigner(String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    byte[] respBytes = transmit(MgmtAction.getSigner, req);
    return parse(respBytes, MgmtResponse.GetSigner.class).getResult();
  }

  @Override
  public void changeSigner(String name, String type, String conf, String base64Cert) throws CaMgmtException {
    MgmtRequest.ChangeSigner req = new MgmtRequest.ChangeSigner();
    req.setName(name);
    req.setType(type);
    req.setConf(conf);
    req.setBase64Cert(base64Cert);
    voidTransmit(MgmtAction.changeSigner, req);
  }

  @Override
  public void addPublisher(PublisherEntry entry) throws CaMgmtException {
    MgmtRequest.AddPublisher req = new MgmtRequest.AddPublisher();
    req.setPublisherEntry(entry);
    voidTransmit(MgmtAction.addPublisher, req);
  }

  @Override
  public Set<String> getPublisherNamesForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getPublisherNamesForCa, req);
    return parse(respBytes, MgmtResponse.StringSet.class).getResult();
  }

  @Override
  public List<PublisherEntry> getPublishersForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getPublishersForCa, req);
    return parse(respBytes, MgmtResponse.GetPublischersForCa.class).getResult();
  }

  @Override
  public PublisherEntry getPublisher(String publisherName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(publisherName);
    byte[] respBytes = transmit(MgmtAction.getPublisher, req);
    return parse(respBytes, MgmtResponse.GetPublisher.class).getResult();
  }

  @Override
  public void removePublisher(String publisherName) throws CaMgmtException {
    removeEntity(MgmtAction.removePublisher, publisherName);
  }

  @Override
  public void changePublisher(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(MgmtAction.changePublisher, req);
  }

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    MgmtRequest.RevokeCa req = new MgmtRequest.RevokeCa();
    req.setCaName(caName);
    req.setRevocationInfo(revocationInfo);
    voidTransmit(MgmtAction.revokeCa, req);
  }

  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    voidTransmit(MgmtAction.unrevokeCa, req);
  }

  @Override
  public void revokeCertificate(String caName, BigInteger serialNumber, CrlReason reason, Instant invalidityTime)
      throws CaMgmtException {
    MgmtRequest.RevokeCertificate req = new MgmtRequest.RevokeCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    req.setReason(reason);
    req.setInvalidityTime(invalidityTime);
    voidTransmit(MgmtAction.revokeCertificate, req);
  }

  @Override
  public void unsuspendCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.UnsuspendCertificate req = new MgmtRequest.UnsuspendCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    voidTransmit(MgmtAction.unsuspendCertificate, req);
  }

  @Override
  public void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.RemoveCertificate req = new MgmtRequest.RemoveCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    voidTransmit(MgmtAction.removeCertificate, req);
  }

  @Override
  public X509Cert generateCrossCertificate(String caName, String profileName, byte[] encodedCsr,
                                           byte[] encodedTargetCert, Instant notBefore, Instant notAfter)
      throws CaMgmtException {
    MgmtRequest.GenerateCrossCertificate req = new MgmtRequest.GenerateCrossCertificate();
    req.setCaName(caName);
    req.setProfileName(profileName);
    req.setEncodedCsr(encodedCsr);
    req.setEncodedTargetCert(encodedTargetCert);
    req.setNotBefore(notBefore);
    req.setNotAfter(notAfter);

    byte[] respBytes = transmit(MgmtAction.generateCrossCertificate, req);
    return parseCert(parse(respBytes, MgmtResponse.ByteArray.class).getResult());
  }

  @Override
  public X509Cert generateCertificate(
      String caName, String profileName, byte[] encodedCsr, Instant notBefore, Instant notAfter)
      throws CaMgmtException {
    MgmtRequest.GenerateCert req = new MgmtRequest.GenerateCert();
    req.setCaName(caName);
    req.setProfileName(profileName);
    req.setEncodedCsr(encodedCsr);
    req.setNotBefore(notBefore);
    req.setNotAfter(notAfter);

    byte[] respBytes = transmit(MgmtAction.generateCertificate, req);
    return parseCert(parse(respBytes, MgmtResponse.ByteArray.class).getResult());
  }

  @Override
  public KeyCertBytesPair generateKeyCert(
      String caName, String profileName, String subject, Instant notBefore, Instant notAfter) throws CaMgmtException {
    MgmtRequest.GenerateKeyCert req = new MgmtRequest.GenerateKeyCert();
    req.setCaName(caName);
    req.setProfileName(profileName);
    req.setSubject(subject);
    req.setNotBefore(notBefore);
    req.setNotAfter(notAfter);

    byte[] respBytes = transmit(MgmtAction.generateKeyCert, req);
    MgmtResponse.KeyCertBytes resp = parse(respBytes, MgmtResponse.KeyCertBytes.class);
    return new KeyCertBytesPair(resp.getKey(), resp.getCert());
  }

  @Override
  public X509Cert generateRootCa(
      CaEntry caEntry, String certprofileName, String subject, String serialNumber, Instant notBefore, Instant notAfter)
      throws CaMgmtException {
    MgmtRequest.GenerateRootCa req = new MgmtRequest.GenerateRootCa();
    req.setCaEntry(caEntry);
    req.setCertprofileName(certprofileName);
    req.setSubject(subject);
    req.setSerialNumber(serialNumber);
    req.setNotBefore(notBefore);
    req.setNotAfter(notAfter);

    byte[] respBytes = transmit(MgmtAction.generateRootCa, req);
    return parseCert(parse(respBytes, MgmtResponse.ByteArray.class).getResult());
  }

  @Override
  public X509CRLHolder generateCrlOnDemand(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.generateCrlOnDemand, req);
    return parseCrl(respBytes);
  }

  @Override
  public X509CRLHolder getCrl(String caName, BigInteger crlNumber) throws CaMgmtException {
    MgmtRequest.GetCrl req = new MgmtRequest.GetCrl();
    req.setCaName(caName);
    req.setCrlNumber(crlNumber);
    byte[] respBytes = transmit(MgmtAction.getCrl, req);
    return parseCrl(respBytes);
  }

  @Override
  public X509CRLHolder getCurrentCrl(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getCurrentCrl, req);
    return parseCrl(respBytes);
  }

  @Override
  public CertWithRevocationInfo getCert(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.GetCert req = new MgmtRequest.GetCert();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(MgmtAction.getCert, req);
    MgmtResponse.GetCert resp = parse(respBytes, MgmtResponse.GetCert.class);
    try {
      return resp.getResult() == null ? null : resp.getResult().toCertWithRevocationInfo();
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse the certificate", ex);
    }
  }

  @Override
  public CertWithRevocationInfo getCert(X500Name issuer, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.GetCert req = new MgmtRequest.GetCert();
    try {
      req.setEncodedIssuerDn(issuer.getEncoded());
    } catch (IOException ex) {
      throw new CaMgmtException("could not encode issuer", ex);
    }
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(MgmtAction.getCert, req);
    MgmtResponse.GetCert resp = parse(respBytes, MgmtResponse.GetCert.class);
    try {
      return resp.getResult().toCertWithRevocationInfo();
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse the certificate", ex);
    }
  }

  @Override
  public void loadConf(byte[] zippedConfBytes) throws CaMgmtException, IOException {
    try (InputStream is = new ByteArrayInputStream(zippedConfBytes)) {
      loadConfAndClose(is);
    }
  }

  @Override
  public void loadConfAndClose(InputStream zippedConfStream) throws CaMgmtException, IOException {
    MgmtRequest.LoadConf req = new MgmtRequest.LoadConf();
    req.setConfBytes(IoUtil.readAllBytes(zippedConfStream));
    voidTransmit(MgmtAction.loadConf, req);
  }

  @Override
  public InputStream exportConf(List<String> caNames) throws CaMgmtException {
    MgmtRequest.ExportConf req = new MgmtRequest.ExportConf();
    req.setCaNames(caNames);
    byte[] respBytes = transmit(MgmtAction.exportConf, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return new ByteArrayInputStream(resp.getResult());
  }

  @Override
  public List<CertListInfo> listCertificates(String caName, X500Name subjectPattern, Instant validFrom,
                                             Instant validTo, CertListOrderBy orderBy, int numEntries)
      throws CaMgmtException {
    MgmtRequest.ListCertificates req = new MgmtRequest.ListCertificates();
    req.setCaName(caName);
    if (subjectPattern != null) {
      try {
        req.setEncodedSubjectDnPattern(subjectPattern.getEncoded());
      } catch (IOException ex) {
        throw new CaMgmtException("could not parse subjectPattern", ex);
      }
    }

    req.setValidFrom(validFrom);
    req.setValidTo(validTo);
    req.setOrderBy(orderBy);
    req.setNumEntries(numEntries);

    byte[] respBytes = transmit(MgmtAction.listCertificates, req);
    return parse(respBytes, MgmtResponse.ListCertificates.class).getResult();
  }

  @Override
  public Set<String> getSupportedSignerTypes() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getSupportedSignerTypes, null);
    return parse(respBytes, MgmtResponse.StringSet.class).getResult();
  }

  @Override
  public Set<String> getSupportedCertprofileTypes() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getSupportedCertprofileTypes, null);
    return parse(respBytes, MgmtResponse.StringSet.class).getResult();
  }

  @Override
  public Set<String> getSupportedPublisherTypes() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getSupportedPublisherTypes, null);
    return parse(respBytes, MgmtResponse.StringSet.class).getResult();
  }

  @Override
  public String getTokenInfoP11(String module, Integer slotIndex, boolean verbose) throws CaMgmtException {
    MgmtRequest.TokenInfoP11 req = new MgmtRequest.TokenInfoP11(module, slotIndex, verbose);
    byte[] respBytes = transmit(MgmtAction.tokenInfoP11, req);
    return parse(respBytes, MgmtResponse.StringResponse.class).getResult();
  }

  private X509Cert parseCert(byte[] certBytes) throws CaMgmtException {
    try {
      return X509Util.parseCert(certBytes);
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse X.509 certificate", ex);
    }
  }

  private X509CRLHolder parseCrl(byte[] respBytes) throws CaMgmtException {
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);

    try {
      return X509Util.parseCrl(resp.getResult());
    } catch (CRLException ex) {
      throw new CaMgmtException("could not parse X.509 CRL", ex);
    }
  }

  private void removeEntity(MgmtAction action, String name) throws CaMgmtException {
    voidTransmit(action, new MgmtRequest.Name(name));
  }

  private void voidTransmit(MgmtAction action, MgmtRequest req) throws CaMgmtException {
    transmit(action, req, true);
  }

  private byte[] transmit(MgmtAction action, MgmtRequest req) throws CaMgmtException {
    return transmit(action, req, false);
  }

  private byte[] transmit(MgmtAction action, MgmtRequest req, boolean voidReturn) throws CaMgmtException {
    initIfNotDone();

    byte[] reqBytes = req == null ? null : CaJson.toJSONBytes(req);
    int size = reqBytes == null ? 0 : reqBytes.length;

    URL url = actionUrlMap.get(action);

    try {
      HttpURLConnection httpUrlConnection = IoUtil.openHttpConn(url);

      if (httpUrlConnection instanceof HttpsURLConnection) {
        if (sslSocketFactory != null) {
          ((HttpsURLConnection) httpUrlConnection).setSSLSocketFactory(sslSocketFactory);
        }
        if (hostnameVerifier != null) {
          ((HttpsURLConnection) httpUrlConnection).setHostnameVerifier(hostnameVerifier);
        }
      }

      httpUrlConnection.setDoOutput(true);
      httpUrlConnection.setUseCaches(false);

      httpUrlConnection.setRequestMethod("POST");
      httpUrlConnection.setRequestProperty("Content-Type", REQUEST_CT);
      httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
      OutputStream outputstream = httpUrlConnection.getOutputStream();
      if (size != 0) {
        outputstream.write(reqBytes);
      }
      outputstream.flush();

      if (httpUrlConnection.getResponseCode() == HttpURLConnection.HTTP_OK) {
        InputStream in = httpUrlConnection.getInputStream();

        boolean inClosed = false;
        try {
          String responseContentType = httpUrlConnection.getContentType();
          if (!RESPONSE_CT.equals(responseContentType)) {
            throw new CaMgmtException("bad response: mime type " + responseContentType + " not supported!");
          }

          if (voidReturn) {
            return null;
          } else {
            inClosed = true;
            return IoUtil.readAllBytesAndClose(httpUrlConnection.getInputStream());
          }
        } finally {
          if (in != null & !inClosed) {
            in.close();
          }
        }
      } else {
        String errorMessage = httpUrlConnection.getHeaderField(HttpConstants.HEADER_XIPKI_ERROR);
        if (errorMessage == null) {
          StringBuilder sb = new StringBuilder(100);
          sb.append("server returns ").append(httpUrlConnection.getResponseCode());
          String respMsg = httpUrlConnection.getResponseMessage();
          if (StringUtil.isNotBlank(respMsg)) {
            sb.append(" ").append(respMsg);
          }
          throw new CaMgmtException(sb.toString());
        } else {
          throw new CaMgmtException(errorMessage);
        }
      }
    } catch (IOException ex) {
      throw new CaMgmtException("IOException while sending message to the server: " + ex.getMessage(), ex);
    }
  } // method transmit

  private static <T extends MgmtResponse> T parse(byte[] bytes, Class<T> clazz)
      throws CaMgmtException {
    try {
      return CaJson.parseObject(bytes, clazz);
    } catch (RuntimeException ex) {
      throw new CaMgmtException("cannot parse response " + clazz + " from byte[]", ex);
    }
  }

}
