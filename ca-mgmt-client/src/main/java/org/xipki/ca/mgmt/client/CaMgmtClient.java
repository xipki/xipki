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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.MgmtEntry;
import org.xipki.ca.api.mgmt.MgmtMessage.CaEntryWrapper;
import org.xipki.ca.api.mgmt.MgmtMessage.MgmtAction;
import org.xipki.ca.api.mgmt.MgmtMessage.SignerEntryWrapper;
import org.xipki.ca.api.mgmt.MgmtRequest;
import org.xipki.ca.api.mgmt.MgmtResponse;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;
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
 * CA management client via REST API.
 *
 * @author Lijun Liao
 */

public class CaMgmtClient implements CaManager {

  private static final String REQUEST_CT = "application/json";

  private static final String RESPONSE_CT = "application/json";

  private final Map<MgmtAction, URL> actionUrlMap = new HashMap<>(50);

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
  } // method initIfNotDone

  public void setServerUrl(String serverUrl) throws MalformedURLException {
    Args.notBlank(serverUrl, "serverUrl");
    this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";

    for (MgmtAction action : MgmtAction.values()) {
      actionUrlMap.put(action, new URL(this.serverUrl + action));
    }
  } // method setServerUrl

  public void setSslContextConf(SslContextConf sslContextConf) {
    this.sslContextConf = sslContextConf;
  } // method setSslContextConf

  @Override
  public CaSystemStatus getCaSystemStatus() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getCaSystemStatus, null);
    MgmtResponse.GetCaSystemStatus resp = parse(respBytes, MgmtResponse.GetCaSystemStatus.class);
    return resp.getResult();
  } // method getCaSystemStatus

  @Override
  public void unlockCa() throws CaMgmtException {
    voidTransmit(MgmtAction.unlockCa, null);
  } // method unlockCa

  @Override
  public void notifyCaChange() throws CaMgmtException {
    voidTransmit(MgmtAction.notifyCaChange, null);
  } // method notifyCaChange

  @Override
  public void republishCertificates(String caName, List<String> publisherNames, int numThreads)
      throws CaMgmtException {
    MgmtRequest.RepublishCertificates req = new MgmtRequest.RepublishCertificates();
    req.setCaName(caName);
    req.setPublisherNames(publisherNames);
    req.setNumThreads(numThreads);
    voidTransmit(MgmtAction.republishCertificates, req);
  } // method republishCertificates

  @Override
  public void clearPublishQueue(String caName, List<String> publisherNames) throws CaMgmtException {
    MgmtRequest.ClearPublishQueue req = new MgmtRequest.ClearPublishQueue();
    req.setCaName(caName);
    req.setPublisherNames(publisherNames);
    voidTransmit(MgmtAction.clearPublishQueue, req);
  } // class clearPublishQueue

  @Override
  public void removeCa(String caName) throws CaMgmtException {
    removeEntity(MgmtAction.removeCa, caName);
  } // method removeCa

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
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  } // method getAliasesForCa

  @Override
  public String getCaNameForAlias(String aliasName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(aliasName);
    byte[] respBytes = transmit(MgmtAction.getCaNameForAlias, req);
    MgmtResponse.StringResponse resp = parse(respBytes, MgmtResponse.StringResponse.class);
    return resp.getResult();
  } // method getCaNameForAlias

  @Override
  public Set<String> getCaAliasNames() throws CaMgmtException {
    return getNames(MgmtAction.getCaAliasNames);
  }

  @Override
  public Set<String> getCertprofileNames() throws CaMgmtException {
    return getNames(MgmtAction.getCertprofileNames);
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
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  } // method getNames

  @Override
  public void addCa(MgmtEntry.Ca caEntry) throws CaMgmtException {
    MgmtRequest.AddCa req = new MgmtRequest.AddCa();
    req.setCaEntry(new CaEntryWrapper(caEntry));
    voidTransmit(MgmtAction.addCa, req);
  } // method addCa

  @Override
  public MgmtEntry.Ca getCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getCa, req);
    MgmtResponse.GetCa resp = parse(respBytes, MgmtResponse.GetCa.class);
    try {
      return resp.getResult().toCaEntry();
    } catch (CertificateException | InvalidConfException ex) {
      throw new CaMgmtException("could not convert CaEntryWrapper to CaEntry", ex);
    }
  } // method getCa

  @Override
  public void changeCa(MgmtEntry.ChangeCa changeCaEntry) throws CaMgmtException {
    MgmtRequest.ChangeCa req = new MgmtRequest.ChangeCa();
    req.setChangeCaEntry(changeCaEntry);
    voidTransmit(MgmtAction.changeCa, req);
  } // method changeCa

  @Override
  public void removeCertprofileFromCa(String profileName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setEntityName(profileName);
    req.setCaName(caName);
    voidTransmit(MgmtAction.removeCertprofileFromCa, req);
  } // method removeCertprofileFromCa

  @Override
  public void addCertprofileToCa(String profileName, String caName) throws CaMgmtException {
    MgmtRequest.AddCertprofileToCa req = new MgmtRequest.AddCertprofileToCa();
    req.setProfileName(profileName);
    req.setCaName(caName);
    voidTransmit(MgmtAction.addCertprofileToCa, req);
  } // method addCertprofileToCa

  @Override
  public void removePublisherFromCa(String publisherName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setCaName(caName);
    req.setEntityName(publisherName);
    voidTransmit(MgmtAction.removePublisherFromCa, req);
  } // method removePublisherFromCa

  @Override
  public void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    MgmtRequest.AddPublisherToCa req = new MgmtRequest.AddPublisherToCa();
    req.setPublisherName(publisherName);
    req.setCaName(caName);
    voidTransmit(MgmtAction.addPublisherToCa, req);
  } // method addPublisherToCa

  @Override
  public Set<String> getCertprofilesForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getCertprofilesForCa, req);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  } // method

  @Override
  public Set<MgmtEntry.CaHasRequestor> getRequestorsForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getRequestorsForCa, req);
    MgmtResponse.GetRequestorsForCa resp = parse(respBytes, MgmtResponse.GetRequestorsForCa.class);
    return resp.getResult();
  } // method getRequestorsForCa

  @Override
  public MgmtEntry.Requestor getRequestor(String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    byte[] respBytes = transmit(MgmtAction.getRequestor, req);
    MgmtResponse.GetRequestor resp = parse(respBytes, MgmtResponse.GetRequestor.class);
    return resp.getResult();
  } // method getRequestor

  @Override
  public void addRequestor(MgmtEntry.Requestor requestorEntry) throws CaMgmtException {
    MgmtRequest.AddRequestor req = new MgmtRequest.AddRequestor();
    req.setRequestorEntry(requestorEntry);
    voidTransmit(MgmtAction.addRequestor, req);
  } // method addRequestor

  @Override
  public void removeRequestor(String requestorName) throws CaMgmtException {
    removeEntity(MgmtAction.removeRequestor, requestorName);
  } // method removeRequestor

  @Override
  public void changeRequestor(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(MgmtAction.changeRequestor, req);
  } // method changeRequestor

  @Override
  public void removeRequestorFromCa(String requestorName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setCaName(caName);
    req.setEntityName(requestorName);
    voidTransmit(MgmtAction.removeRequestorFromCa, req);
  } // method removeRequestorFromCa

  @Override
  public void addRequestorToCa(MgmtEntry.CaHasRequestor requestor, String caName)
      throws CaMgmtException {
    MgmtRequest.AddRequestorToCa req = new MgmtRequest.AddRequestorToCa();
    req.setRequestor(requestor);
    req.setCaName(caName);
    voidTransmit(MgmtAction.addRequestorToCa, req);
  } // method addRequestorToCa

  @Override
  public void removeUserFromCa(String userName, String caName) throws CaMgmtException {
    MgmtRequest.RemoveEntityFromCa req = new MgmtRequest.RemoveEntityFromCa();
    req.setEntityName(userName);
    req.setCaName(caName);
    voidTransmit(MgmtAction.removeUserFromCa, req);
  } // method removeUserFromCa

  @Override
  public void addUserToCa(MgmtEntry.CaHasUser user, String caName) throws CaMgmtException {
    MgmtRequest.AddUserToCa req = new MgmtRequest.AddUserToCa();
    req.setCaName(caName);
    req.setUser(user);
    voidTransmit(MgmtAction.addUserToCa, req);
  } // method addUserToCa

  @Override
  public Map<String, MgmtEntry.CaHasUser> getCaHasUsersForUser(String user) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(user);
    byte[] respBytes = transmit(MgmtAction.getCaHasUsersForUser, req);
    MgmtResponse.GetCaHasUsersForUser resp =
        parse(respBytes, MgmtResponse.GetCaHasUsersForUser.class);
    return resp.getResult();
  } // method getCaHasUsersForUser

  @Override
  public MgmtEntry.Certprofile getCertprofile(String profileName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(profileName);
    byte[] respBytes = transmit(MgmtAction.getCertprofile, req);
    MgmtResponse.GetCertprofile resp = parse(respBytes, MgmtResponse.GetCertprofile.class);
    return resp.getResult();
  } // method getCertprofile

  @Override
  public void removeCertprofile(String profileName) throws CaMgmtException {
    removeEntity(MgmtAction.removeCertprofile, profileName);
  } // method removeCertprofile

  @Override
  public void changeCertprofile(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(MgmtAction.changeCertprofile, req);
  } // method changeCertprofile

  @Override
  public void addCertprofile(MgmtEntry.Certprofile certprofileEntry) throws CaMgmtException {
    MgmtRequest.AddCertprofile req = new MgmtRequest.AddCertprofile();
    req.setCertprofileEntry(certprofileEntry);
    voidTransmit(MgmtAction.addCertprofile, req);
  } // method addCertprofile

  @Override
  public void addSigner(MgmtEntry.Signer signerEntry) throws CaMgmtException {
    MgmtRequest.AddSigner req = new MgmtRequest.AddSigner();
    req.setSignerEntry(new SignerEntryWrapper(signerEntry));
    voidTransmit(MgmtAction.addSigner, req);
  } // method addSigner

  @Override
  public void removeSigner(String name) throws CaMgmtException {
    removeEntity(MgmtAction.removeSigner, name);
  } // method removeSigner

  @Override
  public MgmtEntry.Signer getSigner(String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    byte[] respBytes = transmit(MgmtAction.getSigner, req);
    MgmtResponse.GetSigner resp = parse(respBytes, MgmtResponse.GetSigner.class);
    return resp.getResult().toSignerEntry();
  } // method getSigner

  @Override
  public void changeSigner(String name, String type, String conf, String base64Cert)
      throws CaMgmtException {
    MgmtRequest.ChangeSigner req = new MgmtRequest.ChangeSigner();
    req.setName(name);
    req.setType(type);
    req.setConf(conf);
    req.setBase64Cert(base64Cert);
    voidTransmit(MgmtAction.changeSigner, req);
  } // method changeSigner

  @Override
  public void addPublisher(MgmtEntry.Publisher entry) throws CaMgmtException {
    MgmtRequest.AddPublisher req = new MgmtRequest.AddPublisher();
    req.setPublisherEntry(entry);
    voidTransmit(MgmtAction.addPublisher, req);
  } // method addPublisher

  @Override
  public List<MgmtEntry.Publisher> getPublishersForCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getPublishersForCa, req);
    MgmtResponse.GetPublischersForCa resp =
        parse(respBytes, MgmtResponse.GetPublischersForCa.class);
    return resp.getResult();
  } // method getPublishersForCa

  @Override
  public MgmtEntry.Publisher getPublisher(String publisherName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(publisherName);
    byte[] respBytes = transmit(MgmtAction.getPublisher, req);
    MgmtResponse.GetPublisher resp = parse(respBytes, MgmtResponse.GetPublisher.class);
    return resp.getResult();
  } // method getPublisher

  @Override
  public void removePublisher(String publisherName) throws CaMgmtException {
    removeEntity(MgmtAction.removePublisher, publisherName);
  } // method removePublisher

  @Override
  public void changePublisher(String name, String type, String conf) throws CaMgmtException {
    MgmtRequest.ChangeTypeConfEntity req = new MgmtRequest.ChangeTypeConfEntity(name, type, conf);
    voidTransmit(MgmtAction.changePublisher, req);
  } // method changePublisher

  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    MgmtRequest.RevokeCa req = new MgmtRequest.RevokeCa();
    req.setCaName(caName);
    req.setRevocationInfo(revocationInfo);
    voidTransmit(MgmtAction.revokeCa, req);
  } // method revokeCa

  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    voidTransmit(MgmtAction.unrevokeCa, req);
  } // method unrevokeCa

  @Override
  public void revokeCertificate(String caName, BigInteger serialNumber, CrlReason reason,
      Date invalidityTime) throws CaMgmtException {
    MgmtRequest.RevokeCertificate req = new MgmtRequest.RevokeCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    req.setReason(reason);
    req.setInvalidityTime(invalidityTime);
    voidTransmit(MgmtAction.revokeCertficate, req);
  } // method revokeCertificate

  @Override
  public void unrevokeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.UnrevokeCertificate req = new MgmtRequest.UnrevokeCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    voidTransmit(MgmtAction.unrevokeCertificate, req);
  } // method unrevokeCertificate

  @Override
  public void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.RemoveCertificate req = new MgmtRequest.RemoveCertificate();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    voidTransmit(MgmtAction.removeCertificate, req);
  } // method removeCertificate

  @Override
  public X509Cert generateCertificate(String caName, String profileName,
      byte[] encodedCsr, Date notBefore, Date notAfter) throws CaMgmtException {
    MgmtRequest.GenerateCertificate req = new MgmtRequest.GenerateCertificate();
    req.setCaName(caName);
    req.setProfileName(profileName);
    req.setEncodedCsr(encodedCsr);
    req.setNotBefore(notBefore);
    req.setNotAfter(notAfter);

    byte[] respBytes = transmit(MgmtAction.generateCertificate, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return parseCert(resp.getResult());
  } // method generateCertificate

  @Override
  public X509Cert generateRootCa(MgmtEntry.Ca caEntry, String certprofileName,
      byte[] encodedCsr, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.GenerateRootCa req = new MgmtRequest.GenerateRootCa();
    req.setCaEntry(new CaEntryWrapper(caEntry));
    req.setCertprofileName(certprofileName);
    req.setEncodedCsr(encodedCsr);
    req.setSerialNumber(serialNumber);

    byte[] respBytes = transmit(MgmtAction.generateRootCa, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return parseCert(resp.getResult());
  } // method generateRootCa

  @Override
  public void addUser(MgmtEntry.AddUser addUserEntry) throws CaMgmtException {
    MgmtRequest.AddUser req = new MgmtRequest.AddUser();
    req.setAddUserEntry(addUserEntry);
    voidTransmit(MgmtAction.addUser, req);
  } // method addUser

  @Override
  public void changeUser(MgmtEntry.ChangeUser changeUserEntry) throws CaMgmtException {
    MgmtRequest.ChangeUser req = new MgmtRequest.ChangeUser();
    req.setChangeUserEntry(changeUserEntry);
    voidTransmit(MgmtAction.changeUser, req);
  } // method changeUser

  @Override
  public void removeUser(String username) throws CaMgmtException {
    removeEntity(MgmtAction.removeUser, username);
  } // method removeUser

  @Override
  public MgmtEntry.User getUser(String username) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(username);
    byte[] respBytes = transmit(MgmtAction.getUser, req);
    MgmtResponse.GetUser resp = parse(respBytes, MgmtResponse.GetUser.class);
    return resp.getResult();
  } // method getUser

  @Override
  public X509CRLHolder generateCrlOnDemand(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.generateCrlOnDemand, req);
    return parseCrl(respBytes);
  } // method generateCrlOnDemand

  @Override
  public X509CRLHolder getCrl(String caName, BigInteger crlNumber) throws CaMgmtException {
    MgmtRequest.GetCrl req = new MgmtRequest.GetCrl();
    req.setCaName(caName);
    req.setCrlNumber(crlNumber);
    byte[] respBytes = transmit(MgmtAction.getCrl, req);
    return parseCrl(respBytes);
  } // method getCrl

  @Override
  public X509CRLHolder getCurrentCrl(String caName) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(caName);
    byte[] respBytes = transmit(MgmtAction.getCurrentCrl, req);
    return parseCrl(respBytes);
  } // method getCurrentCrl

  @Override
  public CertWithRevocationInfo getCert(String caName, BigInteger serialNumber)
      throws CaMgmtException {
    MgmtRequest.GetCert req = new MgmtRequest.GetCert();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(MgmtAction.getCert, req);
    MgmtResponse.GetCert resp = parse(respBytes, MgmtResponse.GetCert.class);
    try {
      return resp.getResult().toCertWithRevocationInfo();
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse the certificate", ex);
    }
  } // method getCert

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
    byte[] respBytes = transmit(MgmtAction.getCert, req);
    MgmtResponse.GetCert resp = parse(respBytes, MgmtResponse.GetCert.class);
    try {
      return resp.getResult().toCertWithRevocationInfo();
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse the certificate", ex);
    }
  } // method getCert

  @Override
  public Map<String, X509Cert> loadConf(InputStream zippedConfStream)
      throws CaMgmtException, IOException {
    MgmtRequest.LoadConf req = new MgmtRequest.LoadConf();
    req.setConfBytes(IoUtil.read(zippedConfStream));
    byte[] respBytes = transmit(MgmtAction.loadConf, req);

    MgmtResponse.LoadConf resp = parse(respBytes, MgmtResponse.LoadConf.class);
    Map<String, byte[]> nameCertMap = resp.getResult();

    if (nameCertMap == null) {
      return null;
    } else {
      Map<String, X509Cert> result = new HashMap<>(nameCertMap.size());
      for (String caname : nameCertMap.keySet()) {
        result.put(caname, parseCert(nameCertMap.get(caname)));
      }
      return result;
    }
  } // method loadConf

  @Override
  public InputStream exportConf(List<String> caNames) throws CaMgmtException, IOException {
    MgmtRequest.ExportConf req = new MgmtRequest.ExportConf();
    req.setCaNames(caNames);
    byte[] respBytes = transmit(MgmtAction.exportConf, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return new ByteArrayInputStream(resp.getResult());
  } // method exportConf

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

    byte[] respBytes = transmit(MgmtAction.listCertificates, req);
    MgmtResponse.ListCertificates resp = parse(respBytes, MgmtResponse.ListCertificates.class);
    return resp.getResult();
  } // method listCertificates

  @Override
  public byte[] getCertRequest(String caName, BigInteger serialNumber) throws CaMgmtException {
    MgmtRequest.GetCertRequest req = new MgmtRequest.GetCertRequest();
    req.setCaName(caName);
    req.setSerialNumber(serialNumber);
    byte[] respBytes = transmit(MgmtAction.getCertRequest, req);
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);
    return resp.getResult();
  } // method getCertRequest

  @Override
  public Set<String> getSupportedSignerTypes() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getSupportedSignerTypes, null);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  } // method getSupportedSignerTypes

  @Override
  public Set<String> getSupportedCertprofileTypes() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getSupportedCertprofileTypes, null);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  } // method getSupportedCertprofileTypes

  @Override
  public Set<String> getSupportedPublisherTypes() throws CaMgmtException {
    byte[] respBytes = transmit(MgmtAction.getSupportedPublisherTypes, null);
    MgmtResponse.StringSet resp = parse(respBytes, MgmtResponse.StringSet.class);
    return resp.getResult();
  } // method getSupportedPublisherTypes

  @Override
  public void refreshTokenForSignerType(String signerType) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(signerType);
    voidTransmit(MgmtAction.refreshTokenForSignerType, req);
  } // method refreshTokenForSignerType

  private X509Cert parseCert(byte[] certBytes) throws CaMgmtException {
    try {
      return X509Util.parseCert(certBytes);
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not parse X.509 certificate", ex);
    }
  } // method parseCert

  private X509CRLHolder parseCrl(byte[] respBytes) throws CaMgmtException {
    MgmtResponse.ByteArray resp = parse(respBytes, MgmtResponse.ByteArray.class);

    try {
      return X509Util.parseCrl(resp.getResult());
    } catch (CRLException ex) {
      throw new CaMgmtException("could not parse X.509 CRL", ex);
    }
  } // method parseCrl

  private void removeEntity(MgmtAction action, String name) throws CaMgmtException {
    MgmtRequest.Name req = new MgmtRequest.Name(name);
    voidTransmit(action, req);
  } // method removeEntity

  private void voidTransmit(MgmtAction action, MgmtRequest req) throws CaMgmtException {
    transmit(action, req, true);
  } // method voidTransmit

  private byte[] transmit(MgmtAction action, MgmtRequest req) throws CaMgmtException {
    return transmit(action, req, false);
  } // method transmit

  private byte[] transmit(MgmtAction action, MgmtRequest req, boolean voidReturn)
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
  } // method transmit

  private static <T extends MgmtResponse> T parse(byte[] bytes, Class<?> clazz)
      throws CaMgmtException {
    try {
      return JSON.parseObject(bytes, clazz);
    } catch (RuntimeException ex) {
      throw new CaMgmtException("cannot parse response " + clazz + " from byte[]", ex);
    }
  } // method parse

}
