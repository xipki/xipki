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

package org.xipki.ca.servlet;

import com.alibaba.fastjson.JSON;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.MgmtMessage.CaEntryWrapper;
import org.xipki.ca.api.mgmt.MgmtMessage.MgmtAction;
import org.xipki.ca.api.mgmt.MgmtMessage.SignerEntryWrapper;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.security.X509Cert;
import org.xipki.util.HttpConstants;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.*;

import static org.xipki.util.Args.notEmpty;
import static org.xipki.util.Args.notNull;

/**
 * CA management servlet.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class HttpMgmtServlet extends HttpServlet {

  private static final class MyException extends Exception {

    private final int status;

    public MyException(int status, String message) {
      super(message);
      this.status = status;
    }

    public int getStatus() {
      return status;
    }

  } // class class

  private static final Logger LOG = LoggerFactory.getLogger(HttpMgmtServlet.class);

  private static final String CT_RESPONSE = "application/json";

  private Set<X509Cert> mgmtCerts;

  private CaManager caManager;

  public void setMgmtCerts(Set<X509Cert> mgmtCerts) {
    this.mgmtCerts = new HashSet<>(notEmpty(mgmtCerts, "mgmtCerts"));
  }

  public void setCaManager(CaManager caManager) {
    this.caManager = notNull(caManager, "caManager");
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      X509Cert clientCert = TlsHelper.getTlsClientCert(request);
      if (clientCert == null) {
        throw new MyException(HttpServletResponse.SC_UNAUTHORIZED,
            "remote management is not permitted if TLS client certificate is not present");
      }

      if (!mgmtCerts.contains(clientCert)) {
        throw new MyException(HttpServletResponse.SC_UNAUTHORIZED,
            "remote management is not permitted to the client without valid certificate");
      }

      String path = (String) request.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

      if (path == null || path.length() < 2) {
        throw new MyException(HttpServletResponse.SC_NOT_FOUND, "no action is specified");
      }

      String actionStr = path.substring(1);
      MgmtAction action = MgmtAction.ofName(actionStr);
      if (action == null) {
        throw new MyException(HttpServletResponse.SC_NOT_FOUND,
            "unknown action '" + actionStr + "'");
      }

      InputStream in = request.getInputStream();
      final MgmtResponse resp;

      switch (action) {
        case addCa: {
          MgmtRequest.AddCa req = parse(in, MgmtRequest.AddCa.class);
          CaEntry caEntry;
          try {
            caEntry = req.getCaEntry().toCaEntry();
          } catch (CertificateException | InvalidConfException ex) {
            LOG.error(action + ": could not build the CaEntry", ex);
            throw new MyException(HttpServletResponse.SC_BAD_REQUEST,
                "could not build the CaEntry: " + ex.getMessage());
          }
          caManager.addCa(caEntry);
          resp = null;
          break;
        }
        case addCaAlias: {
          MgmtRequest.AddCaAlias req = parse(in, MgmtRequest.AddCaAlias.class);
          caManager.addCaAlias(req.getAliasName(), req.getCaName());
          resp = null;
          break;
        }
        case addCertprofile: {
          MgmtRequest.AddCertprofile req = parse(in, MgmtRequest.AddCertprofile.class);
          caManager.addCertprofile(req.getCertprofileEntry());
          resp = null;
          break;
        }
        case addCertprofileToCa: {
          MgmtRequest.AddCertprofileToCa req = parse(in, MgmtRequest.AddCertprofileToCa.class);
          caManager.addCertprofileToCa(req.getProfileName(), req.getCaName());
          resp = null;
          break;
        }
        case addPublisher: {
          MgmtRequest.AddPublisher req = parse(in, MgmtRequest.AddPublisher.class);
          caManager.addPublisher(req.getPublisherEntry());
          resp = null;
          break;
        }
        case addPublisherToCa: {
          MgmtRequest.AddPublisherToCa req = parse(in, MgmtRequest.AddPublisherToCa.class);
          caManager.addPublisherToCa(req.getPublisherName(), req.getCaName());
          resp = null;
          break;
        }
        case addRequestor: {
          MgmtRequest.AddRequestor req = parse(in, MgmtRequest.AddRequestor.class);
          caManager.addRequestor(req.getRequestorEntry());
          resp = null;
          break;
        }
        case addRequestorToCa: {
          MgmtRequest.AddRequestorToCa req = parse(in, MgmtRequest.AddRequestorToCa.class);
          caManager.addRequestorToCa(req.getRequestor(), req.getCaName());
          resp = null;
          break;
        }
        case addSigner: {
          MgmtRequest.AddSigner req = parse(in, MgmtRequest.AddSigner.class);
          caManager.addSigner(req.getSignerEntry().toSignerEntry());
          resp = null;
          break;
        }
        case addUser: {
          MgmtRequest.AddUser req = parse(in, MgmtRequest.AddUser.class);
          caManager.addUser(req.getAddUserEntry());
          resp = null;
          break;
        }
        case addUserToCa: {
          MgmtRequest.AddUserToCa req = parse(in, MgmtRequest.AddUserToCa.class);
          caManager.addUserToCa(req.getUser(), req.getCaName());
          resp = null;
          break;
        }
        case changeCa: {
          MgmtRequest.ChangeCa req = parse(in, MgmtRequest.ChangeCa.class);
          caManager.changeCa(req.getChangeCaEntry());
          resp = null;
          break;
        }
        case changeCertprofile: {
          MgmtRequest.ChangeTypeConfEntity req = parse(in, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changeCertprofile(req.getName(), req.getType(), req.getConf());
          resp = null;
          break;
        }
        case changePublisher: {
          MgmtRequest.ChangeTypeConfEntity req = parse(in, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changePublisher(req.getName(), req.getType(), req.getConf());
          resp = null;
          break;
        }
        case changeRequestor: {
          MgmtRequest.ChangeTypeConfEntity req = parse(in, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changeRequestor(req.getName(), req.getType(), req.getConf());
          resp = null;
          break;
        }
        case changeSigner: {
          MgmtRequest.ChangeSigner req = parse(in, MgmtRequest.ChangeSigner.class);
          caManager.changeSigner(req.getName(), req.getType(), req.getConf(), req.getBase64Cert());
          resp = null;
          break;
        }
        case changeUser: {
          MgmtRequest.ChangeUser req = parse(in, MgmtRequest.ChangeUser.class);
          caManager.changeUser(req.getChangeUserEntry());
          resp = null;
          break;
        }
        case clearPublishQueue: {
          MgmtRequest.ClearPublishQueue req = new MgmtRequest.ClearPublishQueue();
          caManager.clearPublishQueue(req.getCaName(), req.getPublisherNames());
          resp = null;
          break;
        }
        case exportConf: {
          MgmtRequest.ExportConf req = parse(in, MgmtRequest.ExportConf.class);
          InputStream confStream = caManager.exportConf(req.getCaNames());
          resp = new MgmtResponse.ByteArray(IoUtil.read(confStream));
          break;
        }
        case generateCertificate: {
          MgmtRequest.GenerateCertificate req = parse(in, MgmtRequest.GenerateCertificate.class);
          X509Cert cert = caManager.generateCertificate(req.getCaName(),
              req.getProfileName(), req.getEncodedCsr(), req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case generateCrlOnDemand: {
          String caName = getNameFromRequest(in);
          X509CRLHolder crl = caManager.generateCrlOnDemand(caName);
          resp = toByteArray(action, crl);
          break;
        }
        case generateRootCa: {
          MgmtRequest.GenerateRootCa req = parse(in, MgmtRequest.GenerateRootCa.class);

          CaEntry caEntry;
          try {
            caEntry = req.getCaEntry().toCaEntry();
          } catch (CertificateException | InvalidConfException ex) {
            LOG.error(action + ": could not build the CaEntry", ex);
            throw new MyException(HttpServletResponse.SC_BAD_REQUEST,
                "could not build the CaEntry: " + ex.getMessage());
          }

          X509Cert cert = caManager.generateRootCa(caEntry,
              req.getCertprofileName(), req.getSubject(), req.getSerialNumber());
          resp = toByteArray(cert);
          break;
        }
        case getAliasesForCa: {
          String caName = getNameFromRequest(in);
          Set<String> result = caManager.getAliasesForCa(caName);
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getCa: {
          String name = getNameFromRequest(in);
          CaEntry caEntry = caManager.getCa(name);
          if (caEntry == null) {
            throw new CaMgmtException("Unknown CA " + name);
          }
          resp = new MgmtResponse.GetCa(new CaEntryWrapper(caEntry));
          break;
        }
        case getCaAliasNames: {
          Set<String> result = caManager.getCaAliasNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getCaHasUsersForUser: {
          String userName = getNameFromRequest(in);
          Map<String, CaHasUserEntry> result = caManager.getCaHasUsersForUser(userName);
          if (result == null) {
            throw new CaMgmtException("Unknown user " + userName);
          }
          resp = new MgmtResponse.GetCaHasUsersForUser(result);
          break;
        }
        case getCaNameForAlias: {
          String aliasName = getNameFromRequest(in);
          String result = caManager.getCaNameForAlias(aliasName);
          resp = new MgmtResponse.StringResponse(result);
          break;
        }
        case getCaNames: {
          Set<String> result = caManager.getCaNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getCaSystemStatus: {
          CaSystemStatus result = caManager.getCaSystemStatus();
          resp = new MgmtResponse.GetCaSystemStatus(result);
          break;
        }
        case getCert: {
          MgmtRequest.GetCert req = parse(in, MgmtRequest.GetCert.class);
          CertWithRevocationInfo cert;
          if (req.getCaName() != null) {
            cert = caManager.getCert(req.getCaName(), req.getSerialNumber());
          } else {
            X500Name issuer = X500Name.getInstance(req.getEncodedIssuerDn());
            cert = caManager.getCert(issuer, req.getSerialNumber());
          }

          resp = new MgmtResponse.GetCert(new MgmtResponse.CertWithRevocationInfoWrapper(cert));
          break;
        }
        case getCertprofile: {
          String name = getNameFromRequest(in);
          CertprofileEntry result = caManager.getCertprofile(name);
          if (result == null) {
            throw new CaMgmtException("Unknown Certprofile " + name);
          }
          resp = new MgmtResponse.GetCertprofile(result);
          break;
        }
        case getCertprofileNames: {
          Set<String> result = caManager.getCertprofileNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getCertprofilesForCa: {
          String caName = getNameFromRequest(in);
          Set<String> result = caManager.getCertprofilesForCa(caName);
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getCertRequest: {
          MgmtRequest.GetCertRequest req = parse(in, MgmtRequest.GetCertRequest.class);
          byte[] result = caManager.getCertRequest(req.getCaName(), req.getSerialNumber());
          if (result == null) {
            throw new CaMgmtException("Found no CertRequest for CA " + req.getCaName()
                        + " and serialNumber " + req.getSerialNumber());
          }
          resp = new MgmtResponse.ByteArray(result);
          break;
        }
        case getCrl: {
          MgmtRequest.GetCrl req = parse(in, MgmtRequest.GetCrl.class);
          X509CRLHolder crl = caManager.getCrl(req.getCaName(), req.getCrlNumber());
          if (crl == null) {
            throw new CaMgmtException("Found no CRL for CA " + req.getCaName()
                        + " with CRL number " + req.getCrlNumber());
          }
          resp = toByteArray(action, crl);
          break;
        }
        case getCurrentCrl: {
          String caName = getNameFromRequest(in);
          X509CRLHolder crl = caManager.getCurrentCrl(caName);
          if (crl == null) {
            throw new CaMgmtException("No current CRL for CA " + caName);
          }
          resp = toByteArray(action, crl);
          break;
        }
        case getFailedCaNames: {
          Set<String> result = caManager.getFailedCaNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getInactiveCaNames: {
          Set<String> result = caManager.getInactiveCaNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getPublisher: {
          String name = getNameFromRequest(in);
          PublisherEntry result = caManager.getPublisher(name);
          if (result == null) {
            throw new CaMgmtException("Unknown publisher " + name);
          }
          resp = new MgmtResponse.GetPublisher(result);
          break;
        }
        case getPublisherNames: {
          Set<String> result = caManager.getPublisherNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getPublishersForCa: {
          String caName = getNameFromRequest(in);
          List<PublisherEntry> result = caManager.getPublishersForCa(caName);
          resp = new MgmtResponse.GetPublischersForCa(result);
          break;
        }
        case getRequestor: {
          String name = getNameFromRequest(in);
          RequestorEntry result = caManager.getRequestor(name);
          if (result == null) {
            throw new CaMgmtException("Unknown requestor " + name);
          }
          resp = new MgmtResponse.GetRequestor(result);
          break;
        }
        case getRequestorNames: {
          Set<String> result = caManager.getRequestorNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getRequestorsForCa: {
          String caName = getNameFromRequest(in);
          Set<CaHasRequestorEntry> result = caManager.getRequestorsForCa(caName);
          resp = new MgmtResponse.GetRequestorsForCa(result);
          break;
        }
        case getSigner: {
          String name = getNameFromRequest(in);
          SignerEntry result = caManager.getSigner(name);
          if (result == null) {
            throw new CaMgmtException("Unknown signer " + name);
          }
          resp = new MgmtResponse.GetSigner(new SignerEntryWrapper(result));
          break;
        }
        case getSignerNames: {
          Set<String> result = caManager.getSignerNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getSuccessfulCaNames: {
          Set<String> result = caManager.getSuccessfulCaNames();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getSupportedCertprofileTypes: {
          Set<String> result = caManager.getSupportedCertprofileTypes();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getSupportedPublisherTypes: {
          Set<String> result = caManager.getSupportedPublisherTypes();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getSupportedSignerTypes: {
          Set<String> result = caManager.getSupportedSignerTypes();
          resp = new MgmtResponse.StringSet(result);
          break;
        }
        case getUser: {
          String name = getNameFromRequest(in);
          UserEntry result = caManager.getUser(name);
          if (result == null) {
            throw new CaMgmtException("Unknown user " + name);
          }
          resp = new MgmtResponse.GetUser(result);
          break;
        }
        case listCertificates: {
          MgmtRequest.ListCertificates req = parse(in, MgmtRequest.ListCertificates.class);
          X500Name subjectPattern = X500Name.getInstance(req.getEncodedSubjectDnPattern());
          List<CertListInfo> result = caManager.listCertificates(req.getCaName(), subjectPattern,
              req.getValidFrom(), req.getValidTo(), req.getOrderBy(), req.getNumEntries());
          resp = new MgmtResponse.ListCertificates(result);
          break;
        }
        case loadConf: {
          MgmtRequest.LoadConf req = parse(in, MgmtRequest.LoadConf.class);
          Map<String, X509Cert> rootcaNameCertMap =
              caManager.loadConf(new ByteArrayInputStream(req.getConfBytes()));

          if (rootcaNameCertMap == null || rootcaNameCertMap.isEmpty()) {
            resp = new MgmtResponse.LoadConf(null);
          } else {
            Map<String, byte[]> result = new HashMap<>(rootcaNameCertMap.size());
            for (String name : rootcaNameCertMap.keySet()) {
              byte[] encodedCert = rootcaNameCertMap.get(name).getEncoded();
              result.put(name, encodedCert);
            }
            resp = new MgmtResponse.LoadConf(result);
          }

          break;
        }
        case notifyCaChange: {
          caManager.notifyCaChange();
          resp = null;
          break;
        }
        case refreshTokenForSignerType: {
          String type = getNameFromRequest(in);
          caManager.refreshTokenForSignerType(type);
          resp = null;
          break;
        }
        case removeCa: {
          String name = getNameFromRequest(in);
          caManager.removeCa(name);
          resp = null;
          break;
        }
        case removeCaAlias: {
          String name = getNameFromRequest(in);
          caManager.removeCaAlias(name);
          resp = null;
          break;
        }
        case removeCertificate: {
          MgmtRequest.RemoveCertificate req = parse(in, MgmtRequest.RemoveCertificate.class);
          caManager.removeCertificate(req.getCaName(), req.getSerialNumber());
          resp = null;
          break;
        }
        case removeCertprofile: {
          String name = getNameFromRequest(in);
          caManager.removeCertprofile(name);
          resp = null;
          break;
        }
        case removeCertprofileFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(in, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removeCertprofileFromCa(req.getEntityName(), req.getCaName());
          resp = null;
          break;
        }
        case removePublisher: {
          String name = getNameFromRequest(in);
          caManager.removePublisher(name);
          resp = null;
          break;
        }
        case removePublisherFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(in, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removePublisherFromCa(req.getEntityName(), req.getCaName());
          resp = null;
          break;
        }
        case removeRequestor: {
          String name = getNameFromRequest(in);
          caManager.removeRequestor(name);
          resp = null;
          break;
        }
        case removeRequestorFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(in, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removeRequestorFromCa(req.getEntityName(), req.getCaName());
          resp = null;
          break;
        }
        case removeSigner: {
          String name = getNameFromRequest(in);
          caManager.removeSigner(name);
          resp = null;
          break;
        }
        case removeUser: {
          String name = getNameFromRequest(in);
          caManager.removeUser(name);
          resp = null;
          break;
        }
        case removeUserFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(in, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removeUserFromCa(req.getEntityName(), req.getCaName());
          resp = null;
          break;
        }
        case republishCertificates: {
          MgmtRequest.RepublishCertificates req =
              parse(in, MgmtRequest.RepublishCertificates.class);
          caManager.republishCertificates(req.getCaName(), req.getPublisherNames(),
              req.getNumThreads());
          resp = null;
          break;
        }
        case restartCa: {
          String name = getNameFromRequest(in);
          caManager.restartCa(name);
          resp = null;
          break;
        }
        case restartCaSystem: {
          caManager.restartCaSystem();
          resp = null;
          break;
        }
        case revokeCa: {
          MgmtRequest.RevokeCa req = parse(in, MgmtRequest.RevokeCa.class);
          caManager.revokeCa(req.getCaName(), req.getRevocationInfo());
          resp = null;
          break;
        }
        case revokeCertficate: {
          MgmtRequest.RevokeCertificate req = parse(in, MgmtRequest.RevokeCertificate.class);
          caManager.revokeCertificate(req.getCaName(),req.getSerialNumber(),
              req.getReason(), req.getInvalidityTime());
          resp = null;
          break;
        }
        case unlockCa: {
          caManager.unlockCa();
          resp = null;
          break;
        }
        case unrevokeCa: {
          String name = getNameFromRequest(in);
          caManager.unrevokeCa(name);
          resp = null;
          break;
        }
        case unrevokeCertificate: {
          MgmtRequest.UnrevokeCertificate req = parse(in, MgmtRequest.UnrevokeCertificate.class);
          caManager.unrevokeCertificate(req.getCaName(), req.getSerialNumber());
          resp = null;
          break;
        }
        default: {
          throw new MyException(HttpServletResponse.SC_NOT_FOUND,
              "unsupported action " + actionStr);
        }
      }

      response.setContentType(CT_RESPONSE);
      response.setStatus(HttpServletResponse.SC_OK);
      if (resp == null) {
        response.setContentLength(0);
      } else {
        byte[] respBytes = JSON.toJSONBytes(resp);
        response.setContentLength(respBytes.length);
        response.getOutputStream().write(respBytes);
      }
    } catch (MyException ex) {
      response.setHeader(HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());
      response.sendError(ex.getStatus());
    } catch (CaMgmtException ex) {
      LOG.error("CaMgmtException", ex);
      response.setHeader(HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      response.flushBuffer();
    }
  } // method doPost

  private static MgmtResponse.ByteArray toByteArray(X509Cert cert) {
    if (cert == null) {
      return new MgmtResponse.ByteArray(null);
    }

    byte[] encoded = cert.getEncoded();
    return new MgmtResponse.ByteArray(encoded);
  } // method toByteArray

  private static MgmtResponse.ByteArray toByteArray(MgmtAction action, X509CRLHolder crl)
      throws MyException {
    if (crl == null) {
      return new MgmtResponse.ByteArray(null);
    }

    byte[] encoded;
    try {
      encoded = crl.getEncoded();
    } catch (IOException ex) {
      LOG.error(action + ": could not encode the generated CRL", ex);
      throw new MyException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "could not encode the generated CRL");
    }

    return new MgmtResponse.ByteArray(encoded);
  } // method toByteArray

  private static String getNameFromRequest(InputStream in)
      throws CaMgmtException {
    MgmtRequest.Name req = parse(in, MgmtRequest.Name.class);
    return req.getName();
  } // method getNameFromRequest

  private static <T extends MgmtRequest> T parse(InputStream in, Class<?> clazz)
      throws CaMgmtException {
    try {
      return JSON.parseObject(in, clazz);
    } catch (RuntimeException | IOException ex) {
      throw new CaMgmtException("cannot parse request " + clazz + " from InputStream");
    }
  } // method parse

}
