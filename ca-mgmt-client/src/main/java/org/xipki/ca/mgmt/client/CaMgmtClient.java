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

package org.xipki.ca.mgmt.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.mgmt.api.CaManager;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.CaSystemStatus;
import org.xipki.ca.mgmt.api.CertListInfo;
import org.xipki.ca.mgmt.api.CertListOrderBy;
import org.xipki.ca.mgmt.api.CertWithRevocationInfo;
import org.xipki.ca.mgmt.api.MgmtEntry;
import org.xipki.ca.mgmt.msg.CaEntryWrapper;
import org.xipki.ca.mgmt.msg.CommAction;
import org.xipki.ca.mgmt.msg.MgmtRequest;
import org.xipki.ca.mgmt.msg.MgmtResponse;
import org.xipki.ca.mgmt.msg.SignerEntryWrapper;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.HttpConstants;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.StringUtil;
import org.xipki.util.http.SslContextConf;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaMgmtClient implements CaManager {

  private static final String REQUEST_CT = "application/json";

  private static final String RESPONSE_CT = "application/json";

  private final Map<CommAction, URL> actionUrlMap = new HashMap<>(50);

  private String serverUrl;

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private SslContextConf sslContextConf;

  private boolean initialized;

  private CaMgmtException initException;

  public CaMgmtClient() {
  }

  public synchronized void initIfNotDone() throws CaMgmtException {
    if (initException != null) {
      throw initException;
    }

    if (initialized) {
      return;
    }

    if (sslContextConf != null && sslContextConf.isUseSslConf()) {
      try {
        sslSocketFactory = sslContextConf.getSslSocketFactory();
        hostnameVerifier = sslContextConf.buildHostnameVerifier();
      } catch (ObjectCreationException ex) {
        initException = new CaMgmtException(
            "could not initialize CaMgmtClient: " + ex.getMessage(), ex);
        throw initException;
      }
    }

    initialized = true;
  }

  public void setServerUrl(String serverUrl) throws MalformedURLException {
    Args.notBlank(serverUrl, "serverUrl");
    this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";

    for (CommAction action : CommAction.values()) {
      actionUrlMap.put(action, new URL(this.serverUrl + action));
    }
  }

  public void setSslContextConf(SslContextConf sslContextConf) {
    this.sslContextConf = sslContextConf;
  }

  @Override
  public CaSystemStatus getCaSystemStatus() throws CaMgmtException {
    byte[] respBytes = transmit(CommAction.getCaSystemStatus, null);
    MgmtResponse.GetCaSystemStatus resp = parse(respBytes, MgmtResponse.GetCaSystemStatus.class);
    return resp.getResult();
  }

  @Override
  public void unlockCa() throws CaMgmtException {
    voidTransmit(CommAction.unlockCa, null);
  }

  @Override
  public void notifyCaChange() throws CaMgmtException {
    voidTransmit(CommAction.notifyCaChange, null);

  }

  @Override
  public void republishCertificates(String caName, List<String> publisherNames, int numThreads)
      throws CaMgmtException {
    MgmtRequest.RepublishCertificates req = new MgmtRequest.RepublishCertificates();
    req.setCaName(caName);
    req.setPublisherNames(publisherNames);
    req.setNumThreads(numThreads);
    voidTransmit(CommAction.republishCertificates, req);
  }

  @Override
  public void clearPublishQueue(String caName, List<String> publisherNames) throws CaMgmtException {
    MgmtRequest.ClearPublishQueue req = new MgmtRequest.ClearPublishQueue();
    req.setCaName(caName);
    req.setPublisherNames(publisherNames);
    voidTransmit(CommAction.clearPublishQueue, req);
  }

  @Override
  public void removeCa(String caName) throws CaMgmtException {
    removeEntity(CommAction.removeCa, caName);
  }

  @Override
  public void restartCaSystem() throws CaMgmtException {
    voidTransmit(CommAction.restartCaSystem, null);
  }

  @Override
  public void addCaAlias(String aliasName, String caName) throws CaMgmtException {
    MgmtRequest.AddCaAlias req = new MgmtRequest.AddCaAlias();
    req.setAliasName(aliasName);
    req.setCaName(caName);
    voidTransmit(CommAction.addCaAlias, req);
  }

  @Override
  public void removeCaAlias(String aliasName) throws CaMgmtException {
    removeEntity(CommAction.removeCaAlias, aliasName);
  }

  @Override
  public Set<String> getAliasesForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(CommAction.getAliasesForCa, req);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  }

  @Override
  public String getCaNameForAlias(String aliasName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(aliasName);
    byte[] respBytes = transmit(CommAction.getCaNameForAlias, req);
    MgmtResponse.StringResponse resp = parse(respBytes, MgmtResponse.StringResponse.class);
    return resp.getResult();
  }

  @Override
  public Set<String> getCaAliasNames() throws CaMgmtException {
    return getNames(CommAction.getCaAliasNames);
  }

  @Override
  public Set<String> getCertprofileNames() throws CaMgmtException {
    return getNames(CommAction.getCertprofileNames);
  }

  @Override
  public Set<String> getPublisherNames() throws CaMgmtException {
    return getNames(CommAction.getPublisherNames);
  }

  @Override
  public Set<String> getRequestorNames() throws CaMgmtException {
    return getNames(CommAction.getRequestorNames);
  }

  @Override
  public Set<String> getSignerNames() throws CaMgmtException {
    return getNames(CommAction.getSignerNames);
  }

  @Override
  public Set<String> getCaNames() throws CaMgmtException {
    return getNames(CommAction.getCaNames);
  }

  @Override
  public Set<String> getSuccessfulCaNames() throws CaMgmtException {
    return getNames(CommAction.getSuccessfulCaNames);
  }

  @Override
  public Set<String> getFailedCaNames() throws CaMgmtException {
    return getNames(CommAction.getFailedCaNames);
  }

  @Override
  public Set<String> getInactiveCaNames() throws CaMgmtException {
    return getNames(CommAction.getInactiveCaNames);
  }

  private Set<String> getNames(CommAction action) throws CaMgmtException {
    byte[] respBytes = transmit(action, null);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  }

  @Override
  public void addCa(MgmtEntry.Ca caEntry) throws CaMgmtException {
    MgmtRequest.AddCa req = new MgmtRequest.AddCa();
    req.setCaEntry(new CaEntryWrapper(caEntry));
    voidTransmit(CommAction.addCa, req);
  }

  @Override
  public MgmtEntry.Ca getCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(CommAction.getCa, req);
    MgmtResponse.GetCa resp = parse(respBytes, MgmtResponse.GetCa.class);
    try {
      return resp.getResult().toCaEntry();
    } catch (CertificateException | InvalidConfException ex) {
      throw new CaMgmtException("could not convert CaEntryWrapper to CaEntry", ex);
    }
  }

  @Override
  public void changeCa(MgmtEntry.ChangeCa changeCaEntry) throws CaMgmtException {
    MgmtRequest.ChangeCa req = new MgmtRequest.ChangeCa();
    req.setChangeCaEntry(changeCaEntry);
    voidTransmit(CommAction.changeCa, req);
  }

  @Override
  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setEntityName(profileName);
    req.setCaName(caName);
    voidTransmit(CommAction.removeCertprofileFromCa, req);
  }

  @Override
  public void addCertprofileToCa(String profileName, String caName) throws CaMgmtException {
    MgmtRequest.AddCertprofileToCa req = new MgmtRequest.AddCertprofileToCa();
    req.setProfileName(profileName);
    req.setCaName(caName);
    voidTransmit(CommAction.addCertprofileToCa, req);
  }

  @Override
  public void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setCaName(caName);
    req.setEntityName(publisherName);
    voidTransmit(CommAction.removePublisherFromCa, req);
  }

  @Override
  public void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    MgmtRequest.AddPublisherToCa req = new MgmtRequest.AddPublisherToCa();
    req.setPublisherName(publisherName);
    req.setCaName(caName);
    voidTransmit(CommAction.addPublisherToCa, req);
  }

  @Override
  public Set<String> getCertprofilesForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(CommAction.getCertprofilesForCa, req);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  }

  @Override
  public Set<MgmtEntry.CaHasRequestor> getRequestorsForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(CommAction.getRequestorsForCa, req);
    MgmtResponse.GetRequestorsForCa resp = parse(respBytes, MgmtResponse.GetRequestorsForCa.class);
    return resp.getResult();
  }

  @Override
  public MgmtEntry.Requestor getRequestor(String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    byte[] respBytes = transmit(CommAction.getRequestor, req);
    MgmtResponse.GetRequestor resp = parse(respBytes, MgmtResponse.GetRequestor.class);
    return resp.getResult();
  }

  @Override
  public void addRequestor(MgmtEntry.Requestor requestorEntry) throws CaMgmtException {
    MgmtRequest.AddRequestor req = new MgmtRequest.AddRequestor();
    req.setRequestorEntry(requestorEntry);
    voidTransmit(CommAction.addRequestor, req);
  }

  @Override
  public void removeRequestor(String requestorName) throws CaMgmtException {
    removeEntity(CommAction.removeRequestor, requestorName);
  }

  @Override
  public void changeRequestor(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(CommAction.changeRequestor, req);
  }

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setCaName(caName);
    req.setEntityName(requestorName);
    voidTransmit(CommAction.removeRequestorFromCa, req);
  }

  @Override
  public void addRequestorToCa(MgmtEntry.CaHasRequestor requestor, String caName)
      throws CaMgmtException {
    MgmtRequest.AddRequestorToCa req = new MgmtRequest.AddRequestorToCa();
    req.setRequestor(requestor);
    req.setCaName(caName);
    voidTransmit(CommAction.addRequestorToCa, req);
  }

  @Override
  public void removeUserFromCa(String userName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setEntityName(userName);
    req.setCaName(caName);
    voidTransmit(CommAction.removeUserFromCa, req);
  }

  @Override
  public void addUserToCa(MgmtEntry.CaHasUser user, String caName) throws CaMgmtException {
    MgmtRequest.AddUserToCa req = new MgmtRequest.AddUserToCa();
    req.setCaName(caName);
    req.setUser(user);
    voidTransmit(CommAction.addUserToCa, req);
  }

  @Override
  public Map<String, MgmtEntry.CaHasUser> getCaHasUsersForUser(String user) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(user);
    byte[] respBytes = transmit(CommAction.getCaHasUsersForUser, req);
    MgmtResponse.GetCaHasUsersForUser resp =
        parse(respBytes, MgmtResponse.GetCaHasUsersForUser.class);
    return resp.getResult();
  }

  @Override
  public MgmtEntry.Certprofile getCertprofile(String profileName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(profileName);
    byte[] respBytes = transmit(CommAction.getCertprofile, req);
    MgmtResponse.GetCertprofile resp = parse(respBytes, MgmtResponse.GetCertprofile.class);
    return resp.getResult();
  }

  @Override
  public void removeCertprofile(String profileName) throws CaMgmtException {
    removeEntity(CommAction.removeCertprofile, profileName);
  }

  @Override
  public void changeCertprofile(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(CommAction.changeCertprofile, req);
  }

  @Override
  public void addCertprofile(MgmtEntry.Certprofile certprofileEntry) throws CaMgmtException {
    MgmtRequest.AddCertprofile req = new MgmtRequest.AddCertprofile();
    req.setCertprofileEntry(certprofileEntry);
    voidTransmit(CommAction.addCertprofile, req);
  }

  @Override
  public void addSigner(MgmtEntry.Signer signerEntry) throws CaMgmtException {
    MgmtRequest.AddSigner req = new MgmtRequest.AddSigner();
    req.setSignerEntry(new SignerEntryWrapper(signerEntry));
    voidTransmit(CommAction.addSigner, req);
  }

  @Override
  public void removeSigner(String name) throws CaMgmtException {
    removeEntity(CommAction.removeSigner, name);
  }

  @Override
  public MgmtEntry.Signer getSigner(String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    byte[] respBytes = transmit(CommAction.getSigner, req);
    MgmtResponse.GetSigner resp = parse(respBytes, MgmtResponse.GetSigner.class);
    return resp.getResult().toSignerEntry();
  }

  @Override
  public void changeSigner(String name, String type, String conf, String base64Cert)
      throws CaMgmtException {
    MgmtRequest.ChangeSigner req = new MgmtRequest.ChangeSigner();
    req.setName(name);
    req.setType(type);
    req.setConf(conf);
    req.setBase64Cert(base64Cert);
    voidTransmit(CommAction.changeSigner, req);
  }

  @Override
  public void addPublisher(MgmtEntry.Publisher entry) throws CaMgmtException {
    MgmtRequest.AddPublisher req = new MgmtRequest.AddPublisher();
    req.setPublisherEntry(entry);
    voidTransmit(CommAction.addPublisher, req);
  }

  @Override
  public List<MgmtEntry.Publisher> getPublishersForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(CommAction.getPublishersForCa, req);
    MgmtResponse.GetPublischersForCa resp =
        parse(respBytes, MgmtResponse.GetPublischersForCa.class);
    return resp.getResult();
  }

  @Override
  public MgmtEntry.Publisher getPublisher(String publisherName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(publisherName);
    byte[] respBytes = transmit(CommAction.getPublisher, req);
    MgmtResponse.GetPublisher resp = parse(respBytes, MgmtResponse.GetPublisher.class);
    return resp.getResult();
  }

  @Override
  public void removePublisher(String publisherName) throws CaMgmtException {
    removeEntity(CommAction.removePublisher, publisherName);
  }

  @Override
  public void changePublisher(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(CommAction.changePublisher, req);
  }

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    MgmtRequest.RevokeCa req = new MgmtRequest.RevokeCa();
    req.setCaName(caName);
    req.setRevocationInfo(revocationInfo);
    voidTransmit(CommAction.revokeCa, req);
  }

  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    voidTransmit(CommAction.unrevokeCa, req);
  }

  @Override
  public void revokeCertificate(String caName, BigInteger serialNumber, CrlReason reason,
      Date invalidityTime) throws CaMgmtException {
    MgmtRequest.RevokeCertificate req = new MgmtRequest.RevokeCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    req.setReason(reason);
    req.setInvalidityTime(invalidityTime);
    voidTransmit(CommAction.revokeCertficate, req);
  }

  @Override
  public void unrevokeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.UnrevokeCertificate req = new MgmtRequest.UnrevokeCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    voidTransmit(CommAction.unrevokeCertificate, req);
  }

  @Override
  public void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.RemoveCertificate req = new MgmtRequest.RemoveCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    voidTransmit(CommAction.removeCertificate, req);
  }

  @Override
  public X509Certificate generateCertificate(String caName, String profileName, byte[] encodedCsr,
      Date notBefore, Date notAfter) throws CaMgmtException {
    MgmtRequest.GenerateCertificate req = new MgmtRequest.GenerateCertificate();
    req.setCaName(caName);
    req.setProfileName(profileName);
    req.setEncodedCsr(encodedCsr);
    req.setNotBefore(notBefore);
    req.setNotAfter(notAfter);

    byte[] respBytes = transmit(CommAction.generateCertificate, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return parseCert(resp.getResult());
  }

  @Override
  public X509Certificate generateRootCa(MgmtEntry.Ca caEntry, String certprofileName,
      byte[] encodedCsr, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.GenerateRootCa req = new MgmtRequest.GenerateRootCa();
    req.setCaEntry(new CaEntryWrapper(caEntry));
    req.setCertprofileName(certprofileName);
    req.setEncodedCsr(encodedCsr);
    req.setSerialNumber(serialNumber);

    byte[] respBytes = transmit(CommAction.generateRootCa, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return parseCert(resp.getResult());
  }

  @Override
  public void addUser(MgmtEntry.AddUser addUserEntry) throws CaMgmtException {
    MgmtRequest.AddUser req = new MgmtRequest.AddUser();
    req.setAddUserEntry(addUserEntry);
    voidTransmit(CommAction.addUser, req);
  }

  @Override
  public void changeUser(MgmtEntry.ChangeUser changeUserEntry) throws CaMgmtException {
    MgmtRequest.ChangeUser req = new MgmtRequest.ChangeUser();
    req.setChangeUserEntry(changeUserEntry);
    voidTransmit(CommAction.changeUser, req);
  }

  @Override
  public void removeUser(String username) throws CaMgmtException {
    removeEntity(CommAction.removeUser, username);
  }

  @Override
  public MgmtEntry.User getUser(String username) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(username);
    byte[] respBytes = transmit(CommAction.getUser, req);
    MgmtResponse.GetUser resp = parse(respBytes, MgmtResponse.GetUser.class);
    return resp.getResult();
  }

  @Override
  public X509CRL generateCrlOnDemand(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(CommAction.generateCrlOnDemand, req);
    return parseCrl(respBytes);
  }

  @Override
  public X509CRL getCrl(String caName, BigInteger crlNumber) throws CaMgmtException {
    MgmtRequest.GetCrl req = new MgmtRequest.GetCrl();
    req.setCaName(caName);
    req.setCrlNumber(crlNumber);
    byte[] respBytes = transmit(CommAction.getCrl, req);
    return parseCrl(respBytes);
  }

  @Override
  public X509CRL getCurrentCrl(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(CommAction.getCurrentCrl, req);
    return parseCrl(respBytes);
  }

  @Override
  public CertWithRevocationInfo getCert(String caName, BigInteger serialNumber)
      throws CaMgmtException {
    MgmtRequest.GetCert req = new MgmtRequest.GetCert();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(CommAction.getCert, req);
    MgmtResponse.GetCert resp = parse(respBytes, MgmtResponse.GetCert.class);
    try {
      return resp.getResult().toCertWithRevocationInfo();
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse the certificate", ex);
    }
  }

  @Override
  public CertWithRevocationInfo getCert(X500Name issuer, BigInteger serialNumber)
      throws CaMgmtException {
    MgmtRequest.GetCert req = new MgmtRequest.GetCert();
    try {
      req.setEncodedIssuerDn(issuer.getEncoded());
    } catch (IOException ex) {
      throw new CaMgmtException("could not encode issuer", ex);
    }
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(CommAction.getCert, req);
    MgmtResponse.GetCert resp = parse(respBytes, MgmtResponse.GetCert.class);
    try {
      return resp.getResult().toCertWithRevocationInfo();
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse the certificate", ex);
    }
  }

  @Override
  public Map<String, X509Certificate> loadConf(InputStream zippedConfStream)
      throws CaMgmtException, IOException {
    MgmtRequest.LoadConf req = new MgmtRequest.LoadConf();
    req.setConfBytes(IoUtil.read(zippedConfStream));
    byte[] respBytes = transmit(CommAction.loadConf, req);

    MgmtResponse.LoadConf resp = parse(respBytes, MgmtResponse.LoadConf.class);
    Map<String, byte[]> nameCertMap = resp.getResult();

    if (nameCertMap == null) {
      return null;
    } else {
      Map<String, X509Certificate> result = new HashMap<>(nameCertMap.size());
      for (String caname : nameCertMap.keySet()) {
        result.put(caname, parseCert(nameCertMap.get(caname)));
      }
      return result;
    }
  }

  @Override
  public InputStream exportConf(List<String> caNames) throws CaMgmtException, IOException {
    MgmtRequest.ExportConf req = new MgmtRequest.ExportConf();
    req.setCaNames(caNames);
    byte[] respBytes = transmit(CommAction.exportConf, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return new ByteArrayInputStream(resp.getResult());
  }

  @Override
  public List<CertListInfo> listCertificates(String caName, X500Name subjectPattern, Date validFrom,
      Date validTo, CertListOrderBy orderBy, int numEntries) throws CaMgmtException {
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

    byte[] respBytes = transmit(CommAction.listCertificates, req);
    MgmtResponse.ListCertificates resp = parse(respBytes, MgmtResponse.ListCertificates.class);
    return resp.getResult();
  }

  @Override
  public byte[] getCertRequest(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.GetCertRequest req = new MgmtRequest.GetCertRequest();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(CommAction.getCertRequest, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return resp.getResult();
  }

  @Override
  public Set<String> getSupportedSignerTypes() throws CaMgmtException {
    byte[] respBytes = transmit(CommAction.getSupportedSignerTypes, null);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  }

  @Override
  public Set<String> getSupportedCertprofileTypes() throws CaMgmtException {
    byte[] respBytes = transmit(CommAction.getSupportedCertprofileTypes, null);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  }

  @Override
  public Set<String> getSupportedPublisherTypes() throws CaMgmtException {
    byte[] respBytes = transmit(CommAction.getSupportedPublisherTypes, null);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  }

  @Override
  public void refreshTokenForSignerType(String signerType) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(signerType);
    voidTransmit(CommAction.refreshTokenForSignerType, req);
  }

  private X509Certificate parseCert(byte[] certBytes) throws CaMgmtException {
    try {
      return X509Util.parseCert(certBytes);
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse X.509 certificate", ex);
    }
  }

  private X509CRL parseCrl(byte[] respBytes) throws CaMgmtException {
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);

    try {
      return X509Util.parseCrl(resp.getResult());
    } catch (CertificateException | CRLException ex) {
      throw new CaMgmtException("could not parse X.509 CRL", ex);
    }
  }

  private void removeEntity(CommAction action, String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    voidTransmit(action, req);
  }

  private void voidTransmit(CommAction action, MgmtRequest req) throws CaMgmtException {
    transmit(action, req, true);
  }

  private byte[] transmit(CommAction action, MgmtRequest req) throws CaMgmtException {
    return transmit(action, req, false);
  }

  private byte[] transmit(CommAction action, MgmtRequest req, boolean voidReturn)
      throws CaMgmtException {
    initIfNotDone();

    byte[] reqBytes = req == null ? null : JSON.toJSONBytes(req);
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
            throw new CaMgmtException(
                "bad response: mime type " + responseContentType + " not supported!");
          }

          if (voidReturn) {
            return null;
          } else {
            inClosed = true;
            return IoUtil.read(httpUrlConnection.getInputStream());
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
      throw new CaMgmtException(
          "IOException while sending message to the server: " + ex.getMessage(), ex);
    }
  }

  private static <T extends MgmtResponse> T parse(byte[] bytes, Class<?> clazz)
      throws CaMgmtException {
    try {
      return JSON.parseObject(bytes, clazz);
    } catch (RuntimeException ex) {
      throw new CaMgmtException("cannot parse response " + clazz + " from byte[]", ex);
    }
  }

}
