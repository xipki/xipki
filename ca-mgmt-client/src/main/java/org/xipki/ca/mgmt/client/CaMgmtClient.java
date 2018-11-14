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
import org.xipki.ca.mgmt.api.AddUserEntry;
import org.xipki.ca.mgmt.api.CaEntry;
import org.xipki.ca.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.mgmt.api.CaHasUserEntry;
import org.xipki.ca.mgmt.api.CaManager;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.CaSystemStatus;
import org.xipki.ca.mgmt.api.CertListInfo;
import org.xipki.ca.mgmt.api.CertListOrderBy;
import org.xipki.ca.mgmt.api.CertWithRevocationInfo;
import org.xipki.ca.mgmt.api.CertprofileEntry;
import org.xipki.ca.mgmt.api.ChangeCaEntry;
import org.xipki.ca.mgmt.api.ChangeUserEntry;
import org.xipki.ca.mgmt.api.PublisherEntry;
import org.xipki.ca.mgmt.api.RequestorEntry;
import org.xipki.ca.mgmt.api.SignerEntry;
import org.xipki.ca.mgmt.api.UserEntry;
import org.xipki.ca.mgmt.msg.AddCaAliasRequest;
import org.xipki.ca.mgmt.msg.AddCaRequest;
import org.xipki.ca.mgmt.msg.AddCertprofileRequest;
import org.xipki.ca.mgmt.msg.AddCertprofileToCaRequest;
import org.xipki.ca.mgmt.msg.AddPublisherRequest;
import org.xipki.ca.mgmt.msg.AddPublisherToCaRequest;
import org.xipki.ca.mgmt.msg.AddRequestorRequest;
import org.xipki.ca.mgmt.msg.AddRequestorToCaRequest;
import org.xipki.ca.mgmt.msg.AddSignerRequest;
import org.xipki.ca.mgmt.msg.AddUserRequest;
import org.xipki.ca.mgmt.msg.AddUserToCaRequest;
import org.xipki.ca.mgmt.msg.ByteArrayResponse;
import org.xipki.ca.mgmt.msg.CaEntryWrapper;
import org.xipki.ca.mgmt.msg.ChangeCaRequest;
import org.xipki.ca.mgmt.msg.ChangeSignerRequest;
import org.xipki.ca.mgmt.msg.ChangeTypeConfEntityRequest;
import org.xipki.ca.mgmt.msg.ChangeUserRequest;
import org.xipki.ca.mgmt.msg.ClearPublishQueueRequest;
import org.xipki.ca.mgmt.msg.CommAction;
import org.xipki.ca.mgmt.msg.CommRequest;
import org.xipki.ca.mgmt.msg.CommResponse;
import org.xipki.ca.mgmt.msg.ExportConfRequest;
import org.xipki.ca.mgmt.msg.GenerateCertificateRequest;
import org.xipki.ca.mgmt.msg.GenerateRootCaRequest;
import org.xipki.ca.mgmt.msg.GetCaHasUsersForUserResponse;
import org.xipki.ca.mgmt.msg.GetCaResponse;
import org.xipki.ca.mgmt.msg.GetCaSysteStatusResponse;
import org.xipki.ca.mgmt.msg.GetCertRequest;
import org.xipki.ca.mgmt.msg.GetCertRequestRequest;
import org.xipki.ca.mgmt.msg.GetCertResponse;
import org.xipki.ca.mgmt.msg.GetCertprofileResponse;
import org.xipki.ca.mgmt.msg.GetCrlRequest;
import org.xipki.ca.mgmt.msg.GetPublischersForCaResponse;
import org.xipki.ca.mgmt.msg.GetPublisherResponse;
import org.xipki.ca.mgmt.msg.GetRequestorResponse;
import org.xipki.ca.mgmt.msg.GetRequestorsForCaResponse;
import org.xipki.ca.mgmt.msg.GetSignerResponse;
import org.xipki.ca.mgmt.msg.GetUserResponse;
import org.xipki.ca.mgmt.msg.ListCertificatesRequest;
import org.xipki.ca.mgmt.msg.ListCertificatesResponse;
import org.xipki.ca.mgmt.msg.LoadConfRequest;
import org.xipki.ca.mgmt.msg.LoadConfResponse;
import org.xipki.ca.mgmt.msg.NameRequest;
import org.xipki.ca.mgmt.msg.RemoveCertificateRequest;
import org.xipki.ca.mgmt.msg.RemoveEntityFromCaRequest;
import org.xipki.ca.mgmt.msg.RepublishCertificatesRequest;
import org.xipki.ca.mgmt.msg.RevokeCaRequest;
import org.xipki.ca.mgmt.msg.RevokeCertificateRequest;
import org.xipki.ca.mgmt.msg.SignerEntryWrapper;
import org.xipki.ca.mgmt.msg.StringResponse;
import org.xipki.ca.mgmt.msg.StringSetResponse;
import org.xipki.ca.mgmt.msg.UnrevokeCertificateRequest;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.util.X509Util;
import org.xipki.util.HttpConstants;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;
import org.xipki.util.http.ssl.SslContextConf;

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
    GetCaSysteStatusResponse resp = parse(respBytes, GetCaSysteStatusResponse.class);
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
    RepublishCertificatesRequest req = new RepublishCertificatesRequest();
    req.setCaName(caName);
    req.setPublisherNames(publisherNames);
    req.setNumThreads(numThreads);
    voidTransmit(CommAction.republishCertificates, req);
  }

  @Override
  public void clearPublishQueue(String caName, List<String> publisherNames) throws CaMgmtException {
    ClearPublishQueueRequest req = new ClearPublishQueueRequest();
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
    AddCaAliasRequest req = new AddCaAliasRequest();
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
    NameRequest req = new NameRequest(caName);
    byte[] respBytes = transmit(CommAction.getAliasesForCa, req);
    StringSetResponse resp = parse(respBytes, StringSetResponse.class);
    return resp.getResult();
  }

  @Override
  public String getCaNameForAlias(String aliasName) throws CaMgmtException {
    NameRequest req = new NameRequest(aliasName);
    byte[] respBytes = transmit(CommAction.getCaNameForAlias, req);
    StringResponse resp = parse(respBytes, StringResponse.class);
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
    StringSetResponse resp = parse(respBytes, StringSetResponse.class);
    return resp.getResult();
  }

  @Override
  public void addCa(CaEntry caEntry) throws CaMgmtException {
    AddCaRequest req = new AddCaRequest();
    req.setCaEntry(new CaEntryWrapper(caEntry));
    voidTransmit(CommAction.addCa, req);
  }

  @Override
  public CaEntry getCa(String caName) throws CaMgmtException {
    NameRequest req = new NameRequest(caName);
    byte[] respBytes = transmit(CommAction.getCa, req);
    GetCaResponse resp = parse(respBytes, GetCaResponse.class);
    try {
      return resp.getResult().toCaEntry();
    } catch (CertificateException | InvalidConfException ex) {
      throw new CaMgmtException("could not convert CaEntryWrapper to CaEntry", ex);
    }
  }

  @Override
  public void changeCa(ChangeCaEntry changeCaEntry) throws CaMgmtException {
    ChangeCaRequest req = new ChangeCaRequest();
    req.setChangeCaEntry(changeCaEntry);
    voidTransmit(CommAction.changeCa, req);
  }

  @Override
  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    RemoveEntityFromCaRequest req = new RemoveEntityFromCaRequest();
    req.setEntityName(profileName);
    req.setCaName(caName);
    voidTransmit(CommAction.removeCertprofileFromCa, req);
  }

  @Override
  public void addCertprofileToCa(String profileName, String caName) throws CaMgmtException {
    AddCertprofileToCaRequest req = new AddCertprofileToCaRequest();
    req.setProfileName(profileName);
    req.setCaName(caName);
    voidTransmit(CommAction.addCertprofileToCa, req);
  }

  @Override
  public void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    RemoveEntityFromCaRequest req = new RemoveEntityFromCaRequest();
    req.setCaName(caName);
    req.setEntityName(publisherName);
    voidTransmit(CommAction.removePublisherFromCa, req);
  }

  @Override
  public void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    AddPublisherToCaRequest req = new AddPublisherToCaRequest();
    req.setPublisherName(publisherName);
    req.setCaName(caName);
    voidTransmit(CommAction.addPublisherToCa, req);
  }

  @Override
  public Set<String> getCertprofilesForCa(String caName) throws CaMgmtException {
    NameRequest req = new NameRequest(caName);
    byte[] respBytes = transmit(CommAction.getCertprofilesForCa, req);
    StringSetResponse resp = parse(respBytes, StringSetResponse.class);
    return resp.getResult();
  }

  @Override
  public Set<CaHasRequestorEntry> getRequestorsForCa(String caName) throws CaMgmtException {
    NameRequest req = new NameRequest(caName);
    byte[] respBytes = transmit(CommAction.getRequestorsForCa, req);
    GetRequestorsForCaResponse resp = parse(respBytes, GetRequestorsForCaResponse.class);
    return resp.getResult();
  }

  @Override
  public RequestorEntry getRequestor(String name) throws CaMgmtException {
    NameRequest req = new NameRequest(name);
    byte[] respBytes = transmit(CommAction.getRequestor, req);
    GetRequestorResponse resp = parse(respBytes, GetRequestorResponse.class);
    return resp.getResult();
  }

  @Override
  public void addRequestor(RequestorEntry requestorEntry) throws CaMgmtException {
    AddRequestorRequest req = new AddRequestorRequest();
    req.setRequestorEntry(requestorEntry);
    voidTransmit(CommAction.addRequestor, req);
  }

  @Override
  public void removeRequestor(String requestorName) throws CaMgmtException {
    removeEntity(CommAction.removeRequestor, requestorName);
  }

  @Override
  public void changeRequestor(String name, String type, String conf) throws CaMgmtException {
    ChangeTypeConfEntityRequest req = new ChangeTypeConfEntityRequest(name, type, conf);
    voidTransmit(CommAction.changeRequestor, req);
  }

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    RemoveEntityFromCaRequest req = new RemoveEntityFromCaRequest();
    req.setCaName(caName);
    req.setEntityName(requestorName);
    voidTransmit(CommAction.removeRequestorFromCa, req);
  }

  @Override
  public void addRequestorToCa(CaHasRequestorEntry requestor, String caName)
      throws CaMgmtException {
    AddRequestorToCaRequest req = new AddRequestorToCaRequest();
    req.setRequestor(requestor);
    req.setCaName(caName);
    voidTransmit(CommAction.addRequestorToCa, req);
  }

  @Override
  public void removeUserFromCa(String userName, String caName) throws CaMgmtException {
    RemoveEntityFromCaRequest req = new RemoveEntityFromCaRequest();
    req.setEntityName(userName);
    req.setCaName(caName);
    voidTransmit(CommAction.removeUserFromCa, req);
  }

  @Override
  public void addUserToCa(CaHasUserEntry user, String caName) throws CaMgmtException {
    AddUserToCaRequest req = new AddUserToCaRequest();
    req.setCaName(caName);
    req.setUser(user);
    voidTransmit(CommAction.addUserToCa, req);
  }

  @Override
  public Map<String, CaHasUserEntry> getCaHasUsersForUser(String user) throws CaMgmtException {
    NameRequest req = new NameRequest(user);
    byte[] respBytes = transmit(CommAction.getCaHasUsersForUser, req);
    GetCaHasUsersForUserResponse resp = parse(respBytes, GetCaHasUsersForUserResponse.class);
    return resp.getResult();
  }

  @Override
  public CertprofileEntry getCertprofile(String profileName) throws CaMgmtException {
    NameRequest req = new NameRequest(profileName);
    byte[] respBytes = transmit(CommAction.getCertprofile, req);
    GetCertprofileResponse resp = parse(respBytes, GetCertprofileResponse.class);
    return resp.getResult();
  }

  @Override
  public void removeCertprofile(String profileName) throws CaMgmtException {
    removeEntity(CommAction.removeCertprofile, profileName);
  }

  @Override
  public void changeCertprofile(String name, String type, String conf) throws CaMgmtException {
    ChangeTypeConfEntityRequest req = new ChangeTypeConfEntityRequest(name, type, conf);
    voidTransmit(CommAction.changeCertprofile, req);
  }

  @Override
  public void addCertprofile(CertprofileEntry certprofileEntry) throws CaMgmtException {
    AddCertprofileRequest req = new AddCertprofileRequest();
    req.setCertprofileEntry(certprofileEntry);
    voidTransmit(CommAction.addCertprofile, req);
  }

  @Override
  public void addSigner(SignerEntry signerEntry) throws CaMgmtException {
    AddSignerRequest req = new AddSignerRequest();
    req.setSignerEntry(new SignerEntryWrapper(signerEntry));
    voidTransmit(CommAction.addSigner, req);
  }

  @Override
  public void removeSigner(String name) throws CaMgmtException {
    removeEntity(CommAction.removeSigner, name);
  }

  @Override
  public SignerEntry getSigner(String name) throws CaMgmtException {
    NameRequest req = new NameRequest(name);
    byte[] respBytes = transmit(CommAction.getSigner, req);
    GetSignerResponse resp = parse(respBytes, GetSignerResponse.class);
    return resp.getResult().toSignerEntry();
  }

  @Override
  public void changeSigner(String name, String type, String conf, String base64Cert)
      throws CaMgmtException {
    ChangeSignerRequest req = new ChangeSignerRequest();
    req.setName(name);
    req.setType(type);
    req.setConf(conf);
    req.setBase64Cert(base64Cert);
    voidTransmit(CommAction.changeSigner, req);
  }

  @Override
  public void addPublisher(PublisherEntry entry) throws CaMgmtException {
    AddPublisherRequest req = new AddPublisherRequest();
    req.setPublisherEntry(entry);
    voidTransmit(CommAction.addPublisher, req);
  }

  @Override
  public List<PublisherEntry> getPublishersForCa(String caName) throws CaMgmtException {
    NameRequest req = new NameRequest(caName);
    byte[] respBytes = transmit(CommAction.getPublishersForCa, req);
    GetPublischersForCaResponse resp = parse(respBytes, GetPublischersForCaResponse.class);
    return resp.getResult();
  }

  @Override
  public PublisherEntry getPublisher(String publisherName) throws CaMgmtException {
    NameRequest req = new NameRequest(publisherName);
    byte[] respBytes = transmit(CommAction.getPublisher, req);
    GetPublisherResponse resp = parse(respBytes, GetPublisherResponse.class);
    return resp.getResult();
  }

  @Override
  public void removePublisher(String publisherName) throws CaMgmtException {
    removeEntity(CommAction.removePublisher, publisherName);
  }

  @Override
  public void changePublisher(String name, String type, String conf) throws CaMgmtException {
    ChangeTypeConfEntityRequest req = new ChangeTypeConfEntityRequest(name, type, conf);
    voidTransmit(CommAction.changePublisher, req);
  }

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    RevokeCaRequest req = new RevokeCaRequest();
    req.setCaName(caName);
    req.setRevocationInfo(revocationInfo);
    voidTransmit(CommAction.revokeCa, req);
  }

  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    NameRequest req = new NameRequest(caName);
    voidTransmit(CommAction.unrevokeCa, req);
  }

  @Override
  public void revokeCertificate(String caName, BigInteger serialNumber, CrlReason reason,
      Date invalidityTime) throws CaMgmtException {
    RevokeCertificateRequest req = new RevokeCertificateRequest();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    req.setReason(reason);
    req.setInvalidityTime(invalidityTime);
    voidTransmit(CommAction.revokeCertficate, req);
  }

  @Override
  public void unrevokeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    UnrevokeCertificateRequest req = new UnrevokeCertificateRequest();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    voidTransmit(CommAction.unrevokeCertificate, req);
  }

  @Override
  public void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    RemoveCertificateRequest req = new RemoveCertificateRequest();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    voidTransmit(CommAction.removeCertificate, req);
  }

  @Override
  public X509Certificate generateCertificate(String caName, String profileName, byte[] encodedCsr,
      Date notBefore, Date notAfter) throws CaMgmtException {
    GenerateCertificateRequest req = new GenerateCertificateRequest();
    req.setCaName(caName);
    req.setProfileName(profileName);
    req.setEncodedCsr(encodedCsr);
    req.setNotBefore(notBefore);
    req.setNotAfter(notAfter);

    byte[] respBytes = transmit(CommAction.generateCertificate, req);
    ByteArrayResponse resp = parse(respBytes, ByteArrayResponse.class);
    return parseCert(resp.getResult());
  }

  @Override
  public X509Certificate generateRootCa(CaEntry caEntry, String certprofileName, byte[] encodedCsr,
      BigInteger serialNumber) throws CaMgmtException {
    GenerateRootCaRequest req = new GenerateRootCaRequest();
    req.setCaEntry(new CaEntryWrapper(caEntry));
    req.setCertprofileName(certprofileName);
    req.setEncodedCsr(encodedCsr);
    req.setSerialNumber(serialNumber);

    byte[] respBytes = transmit(CommAction.generateRootCa, req);
    ByteArrayResponse resp = parse(respBytes, ByteArrayResponse.class);
    return parseCert(resp.getResult());
  }

  @Override
  public void addUser(AddUserEntry addUserEntry) throws CaMgmtException {
    AddUserRequest req = new AddUserRequest();
    req.setAddUserEntry(addUserEntry);
    voidTransmit(CommAction.addUser, req);
  }

  @Override
  public void changeUser(ChangeUserEntry changeUserEntry) throws CaMgmtException {
    ChangeUserRequest req = new ChangeUserRequest();
    req.setChangeUserEntry(changeUserEntry);
    voidTransmit(CommAction.changeUser, req);
  }

  @Override
  public void removeUser(String username) throws CaMgmtException {
    removeEntity(CommAction.removeUser, username);
  }

  @Override
  public UserEntry getUser(String username) throws CaMgmtException {
    NameRequest req = new NameRequest(username);
    byte[] respBytes = transmit(CommAction.getUser, req);
    GetUserResponse resp = parse(respBytes, GetUserResponse.class);
    return resp.getResult();
  }

  @Override
  public X509CRL generateCrlOnDemand(String caName) throws CaMgmtException {
    NameRequest req = new NameRequest(caName);
    byte[] respBytes = transmit(CommAction.generateCrlOnDemand, req);
    return parseCrl(respBytes);
  }

  @Override
  public X509CRL getCrl(String caName, BigInteger crlNumber) throws CaMgmtException {
    GetCrlRequest req = new GetCrlRequest();
    req.setCaName(caName);
    req.setCrlNumber(crlNumber);
    byte[] respBytes = transmit(CommAction.getCrl, req);
    return parseCrl(respBytes);
  }

  @Override
  public X509CRL getCurrentCrl(String caName) throws CaMgmtException {
    NameRequest req = new NameRequest(caName);
    byte[] respBytes = transmit(CommAction.getCurrentCrl, req);
    return parseCrl(respBytes);
  }

  @Override
  public CertWithRevocationInfo getCert(String caName, BigInteger serialNumber)
      throws CaMgmtException {
    GetCertRequest req = new GetCertRequest();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(CommAction.getCert, req);
    GetCertResponse resp = parse(respBytes, GetCertResponse.class);
    try {
      return resp.getResult().toCertWithRevocationInfo();
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse the certificate", ex);
    }
  }

  @Override
  public CertWithRevocationInfo getCert(X500Name issuer, BigInteger serialNumber)
      throws CaMgmtException {
    GetCertRequest req = new GetCertRequest();
    try {
      req.setEncodedIssuerDn(issuer.getEncoded());
    } catch (IOException ex) {
      throw new CaMgmtException("could not encode issuer", ex);
    }
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(CommAction.getCert, req);
    GetCertResponse resp = parse(respBytes, GetCertResponse.class);
    try {
      return resp.getResult().toCertWithRevocationInfo();
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse the certificate", ex);
    }
  }

  @Override
  public Map<String, X509Certificate> loadConf(InputStream zippedConfStream)
      throws CaMgmtException, IOException {
    LoadConfRequest req = new LoadConfRequest();
    req.setConfBytes(IoUtil.read(zippedConfStream));
    byte[] respBytes = transmit(CommAction.loadConf, req);

    LoadConfResponse resp = parse(respBytes, LoadConfResponse.class);
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
    ExportConfRequest req = new ExportConfRequest();
    req.setCaNames(caNames);
    byte[] respBytes = transmit(CommAction.exportConf, req);
    ByteArrayResponse resp = parse(respBytes, ByteArrayResponse.class);
    return new ByteArrayInputStream(resp.getResult());
  }

  @Override
  public List<CertListInfo> listCertificates(String caName, X500Name subjectPattern, Date validFrom,
      Date validTo, CertListOrderBy orderBy, int numEntries) throws CaMgmtException {
    ListCertificatesRequest req = new ListCertificatesRequest();
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
    ListCertificatesResponse resp = parse(respBytes, ListCertificatesResponse.class);
    return resp.getResult();
  }

  @Override
  public byte[] getCertRequest(String caName, BigInteger serialNumber) throws CaMgmtException {
    GetCertRequestRequest req = new GetCertRequestRequest();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(CommAction.getCertRequest, req);
    ByteArrayResponse resp = parse(respBytes, ByteArrayResponse.class);
    return resp.getResult();
  }

  @Override
  public Set<String> getSupportedSignerTypes() throws CaMgmtException {
    byte[] respBytes = transmit(CommAction.getSupportedSignerTypes, null);
    StringSetResponse resp = parse(respBytes, StringSetResponse.class);
    return resp.getResult();
  }

  @Override
  public Set<String> getSupportedCertprofileTypes() throws CaMgmtException {
    byte[] respBytes = transmit(CommAction.getSupportedCertprofileTypes, null);
    StringSetResponse resp = parse(respBytes, StringSetResponse.class);
    return resp.getResult();
  }

  @Override
  public Set<String> getSupportedPublisherTypes() throws CaMgmtException {
    byte[] respBytes = transmit(CommAction.getSupportedPublisherTypes, null);
    StringSetResponse resp = parse(respBytes, StringSetResponse.class);
    return resp.getResult();
  }

  @Override
  public void refreshTokenForSignerType(String signerType) throws CaMgmtException {
    NameRequest req = new NameRequest(signerType);
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
    ByteArrayResponse resp = parse(respBytes, ByteArrayResponse.class);

    try {
      return X509Util.parseCrl(resp.getResult());
    } catch (CertificateException | CRLException ex) {
      throw new CaMgmtException("could not parse X.509 CRL", ex);
    }
  }

  private void removeEntity(CommAction action, String name) throws CaMgmtException {
    NameRequest req = new NameRequest(name);
    voidTransmit(action, req);
  }

  private void voidTransmit(CommAction action, CommRequest req) throws CaMgmtException {
    transmit(action, req, true);
  }

  private byte[] transmit(CommAction action, CommRequest req) throws CaMgmtException {
    return transmit(action, req, false);
  }

  private byte[] transmit(CommAction action, CommRequest req, boolean voidReturn)
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

  private static <T extends CommResponse> T parse(byte[] bytes, Class<?> clazz)
      throws CaMgmtException {
    try {
      return JSON.parseObject(bytes, clazz);
    } catch (RuntimeException ex) {
      throw new CaMgmtException("cannot parse response " + clazz + " from byte[]", ex);
    }
  }

}
