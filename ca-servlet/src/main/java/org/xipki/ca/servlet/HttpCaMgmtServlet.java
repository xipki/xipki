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

package org.xipki.ca.servlet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CaSystemStatus;
import org.xipki.ca.server.mgmt.api.CertListInfo;
import org.xipki.ca.server.mgmt.api.CertWithRevocationInfo;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.RequestorEntry;
import org.xipki.ca.server.mgmt.api.SignerEntry;
import org.xipki.ca.server.mgmt.api.UserEntry;
import org.xipki.ca.server.mgmt.msg.AddCaAliasRequest;
import org.xipki.ca.server.mgmt.msg.AddCaRequest;
import org.xipki.ca.server.mgmt.msg.AddCertprofileRequest;
import org.xipki.ca.server.mgmt.msg.AddCertprofileToCaRequest;
import org.xipki.ca.server.mgmt.msg.AddPublisherRequest;
import org.xipki.ca.server.mgmt.msg.AddPublisherToCaRequest;
import org.xipki.ca.server.mgmt.msg.AddRequestorRequest;
import org.xipki.ca.server.mgmt.msg.AddRequestorToCaRequest;
import org.xipki.ca.server.mgmt.msg.AddSignerRequest;
import org.xipki.ca.server.mgmt.msg.AddUserRequest;
import org.xipki.ca.server.mgmt.msg.AddUserToCaRequest;
import org.xipki.ca.server.mgmt.msg.ByteArrayResponse;
import org.xipki.ca.server.mgmt.msg.CaEntryWrapper;
import org.xipki.ca.server.mgmt.msg.CertWithRevocationInfoWrapper;
import org.xipki.ca.server.mgmt.msg.ChangeCaRequest;
import org.xipki.ca.server.mgmt.msg.ChangeSignerRequest;
import org.xipki.ca.server.mgmt.msg.ChangeTypeConfEntityRequest;
import org.xipki.ca.server.mgmt.msg.ChangeUserRequest;
import org.xipki.ca.server.mgmt.msg.ClearPublishQueueRequest;
import org.xipki.ca.server.mgmt.msg.CommAction;
import org.xipki.ca.server.mgmt.msg.CommRequest;
import org.xipki.ca.server.mgmt.msg.CommResponse;
import org.xipki.ca.server.mgmt.msg.ErrorResponse;
import org.xipki.ca.server.mgmt.msg.ExportConfRequest;
import org.xipki.ca.server.mgmt.msg.GenerateCertificateRequest;
import org.xipki.ca.server.mgmt.msg.GenerateRootCaRequest;
import org.xipki.ca.server.mgmt.msg.GetCaHasUsersForUserResponse;
import org.xipki.ca.server.mgmt.msg.GetCaResponse;
import org.xipki.ca.server.mgmt.msg.GetCaSysteStatusResponse;
import org.xipki.ca.server.mgmt.msg.GetCertRequest;
import org.xipki.ca.server.mgmt.msg.GetCertRequestRequest;
import org.xipki.ca.server.mgmt.msg.GetCertResponse;
import org.xipki.ca.server.mgmt.msg.GetCertprofileResponse;
import org.xipki.ca.server.mgmt.msg.GetCrlRequest;
import org.xipki.ca.server.mgmt.msg.GetPublischersForCaResponse;
import org.xipki.ca.server.mgmt.msg.GetPublisherResponse;
import org.xipki.ca.server.mgmt.msg.GetRequestorResponse;
import org.xipki.ca.server.mgmt.msg.GetRequestorsForCaResponse;
import org.xipki.ca.server.mgmt.msg.GetSignerResponse;
import org.xipki.ca.server.mgmt.msg.GetUserResponse;
import org.xipki.ca.server.mgmt.msg.ListCertificatesRequest;
import org.xipki.ca.server.mgmt.msg.ListCertificatesResponse;
import org.xipki.ca.server.mgmt.msg.LoadConfRequest;
import org.xipki.ca.server.mgmt.msg.LoadConfResponse;
import org.xipki.ca.server.mgmt.msg.NameRequest;
import org.xipki.ca.server.mgmt.msg.RemoveCertificateRequest;
import org.xipki.ca.server.mgmt.msg.RemoveEntityFromCaRequest;
import org.xipki.ca.server.mgmt.msg.RepublishCertificatesRequest;
import org.xipki.ca.server.mgmt.msg.RevokeCaRequest;
import org.xipki.ca.server.mgmt.msg.RevokeCertificateRequest;
import org.xipki.ca.server.mgmt.msg.SignerEntryWrapper;
import org.xipki.ca.server.mgmt.msg.StringResponse;
import org.xipki.ca.server.mgmt.msg.StringSetResponse;
import org.xipki.ca.server.mgmt.msg.UnrevokeCertificateRequest;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

@SuppressWarnings("serial")
public class HttpCaMgmtServlet extends HttpServlet {

  private static final class MyException extends Exception {

    private int status;

    public MyException(int status, String message) {
      super(message);
      this.status = status;
    }

    public int getStatus() {
      return status;
    }

  }

  private static final Logger LOG = LoggerFactory.getLogger(HttpCaMgmtServlet.class);

  private static final String CT_RESPONSE = "application/json";

  private CaManager caManager;

  public void setCaManager(CaManager caManager) {
    this.caManager = ParamUtil.requireNonNull("caManager", caManager);;
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      String path = (String) request.getAttribute(CaServletFilter.ATTR_XIPKI_PATH);

      if (path == null || path.length() < 2) {
        throw new MyException(HttpServletResponse.SC_NOT_FOUND, "no action is specified");
      }

      String actionStr = path.substring(1);
      CommAction action = CommAction.ofName(actionStr);
      if (action == null) {
        throw new MyException(HttpServletResponse.SC_NOT_FOUND,
            "unknown action '" + actionStr + "'");
      }

      InputStream in = request.getInputStream();
      CommResponse resp = null;

      switch (action) {
        case addCa: {
            AddCaRequest req = parse(in, AddCaRequest.class);
            CaEntry caEntry;
            try {
              caEntry = req.getCaEntry().toCaEntry();
            } catch (CertificateException | InvalidConfException ex) {
              LOG.warn(action + ": could not build the CaEntry", ex);
              throw new MyException(HttpServletResponse.SC_BAD_REQUEST,
                  "could not build the CaEntry: " + ex.getMessage());
            }
            caManager.addCa(caEntry);
            break;
        }
        case addCaAlias: {
          AddCaAliasRequest req = parse(in, AddCaAliasRequest.class);
          caManager.addCaAlias(req.getAliasName(), req.getCaName());
          break;
        }
        case addCertprofile: {
          AddCertprofileRequest req = parse(in, AddCertprofileRequest.class);
          caManager.addCertprofile(req.getCertprofileEntry());
          break;
        }
        case addCertprofileToCa: {
          AddCertprofileToCaRequest req = parse(in, AddCertprofileToCaRequest.class);
          caManager.addCertprofileToCa(req.getProfileName(), req.getCaName());
          break;
        }
        case addPublisher: {
          AddPublisherRequest req = parse(in, AddPublisherRequest.class);
          caManager.addPublisher(req.getPublisherEntry());
          break;
        }
        case addPublisherToCa: {
          AddPublisherToCaRequest req = parse(in, AddPublisherRequest.class);
          caManager.addPublisherToCa(req.getPublisherName(), req.getCaName());
          break;
        }
        case addRequestor: {
          AddRequestorRequest req = parse(in, AddRequestorRequest.class);
          caManager.addRequestor(req.getRequestorEntry());
          break;
        }
        case addRequestorToCa: {
          AddRequestorToCaRequest req = parse(in, AddRequestorToCaRequest.class);
          caManager.addRequestorToCa(req.getRequestor(), req.getCaName());
          break;
        }
        case addSigner: {
          AddSignerRequest req = parse(in, AddSignerRequest.class);
          caManager.addSigner(req.getSignerEntry().toSignerEntry());
          break;
        }
        case addUser: {
          AddUserRequest req = parse(in, AddUserRequest.class);
          caManager.addUser(req.getAddUserEntry());
          break;
        }
        case addUserToCa: {
          AddUserToCaRequest req = parse(in, AddUserToCaRequest.class);
          caManager.addUserToCa(req.getUser(), req.getCaName());
          break;
        }
        case changeCa: {
          ChangeCaRequest req = parse(in, ChangeCaRequest.class);
          caManager.changeCa(req.getChangeCaEntry());
          break;
        }
        case changeCertprofile: {
          ChangeTypeConfEntityRequest req = parse(in, ChangeTypeConfEntityRequest.class);
          caManager.changeCertprofile(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changePublisher: {
          ChangeTypeConfEntityRequest req = parse(in, ChangeTypeConfEntityRequest.class);
          caManager.changePublisher(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changeRequestor: {
          ChangeTypeConfEntityRequest req = parse(in, ChangeTypeConfEntityRequest.class);
          caManager.changeRequestor(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changeSigner: {
          ChangeSignerRequest req = parse(in, ChangeSignerRequest.class);
          caManager.changeSigner(req.getName(), req.getType(), req.getConf(), req.getBase64Cert());
          break;
        }
        case changeUser: {
          ChangeUserRequest req = parse(in, ChangeUserRequest.class);
          caManager.changeUser(req.getChangeUserEntry());
          break;
        }
        case clearPublishQueue: {
          ClearPublishQueueRequest req = new ClearPublishQueueRequest();
          caManager.clearPublishQueue(req.getCaName(), req.getPublisherNames());
          break;
        }
        case exportConf: {
          ExportConfRequest req = parse(in, ExportConfRequest.class);
          InputStream confStream = caManager.exportConf(req.getCaNames());
          resp = new ByteArrayResponse(IoUtil.read(confStream));
          break;
        }
        case generateCertificate: {
          GenerateCertificateRequest req = parse(in, GenerateCertificateRequest.class);
          X509Certificate cert = caManager.generateCertificate(req.getCaName(),
              req.getProfileName(), req.getEncodedCsr(), req.getNotBefore(), req.getNotAfter());
          resp = toByteArrayResponse(action, cert);
          break;
        }
        case generateCrlOnDemand: {
          String caName = getNameFromRequest(in);
          X509CRL crl = caManager.generateCrlOnDemand(caName);
          resp = toByteArrayResponse(action, crl);
          break;
        }
        case generateRootCa: {
          GenerateRootCaRequest req = parse(in, GenerateRootCaRequest.class);

          CaEntry caEntry;
          try {
            caEntry = req.getCaEntry().toCaEntry();
          } catch (CertificateException | InvalidConfException ex) {
            LOG.warn(action + ": could not build the CaEntry", ex);
            throw new MyException(HttpServletResponse.SC_BAD_REQUEST,
                "could not build the CaEntry: " + ex.getMessage());
          }

          X509Certificate cert = caManager.generateRootCa(caEntry,
              req.getCertprofileName(), req.getEncodedCsr(), req.getSerialNumber());
          resp = toByteArrayResponse(action, cert);
          break;
        }
        case getAliasesForCa: {
          String caName = getNameFromRequest(in);
          Set<String> result = caManager.getAliasesForCa(caName);
          resp = new StringSetResponse(result);
          break;
        }
        case getCa: {
          String name = getNameFromRequest(in);
          CaEntry caEntry = caManager.getCa(name);
          resp = new GetCaResponse(new CaEntryWrapper(caEntry));
          break;
        }
        case getCaAliasNames: {
          Set<String> result = caManager.getCaAliasNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getCaHasUsersForUser: {
          String userName = getNameFromRequest(in);
          Map<String, CaHasUserEntry> result = caManager.getCaHasUsersForUser(userName);
          resp = new GetCaHasUsersForUserResponse(result);
          break;
        }
        case getCaNameForAlias: {
          String aliasName = getNameFromRequest(in);
          String result = caManager.getCaNameForAlias(aliasName);
          resp = new StringResponse(result);
          break;
        }
        case getCaNames: {
          Set<String> result = caManager.getCaNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getCaSystemStatus: {
          CaSystemStatus result = caManager.getCaSystemStatus();
          resp = new GetCaSysteStatusResponse(result);
          break;
        }
        case getCert: {
          GetCertRequest req = parse(in, GetCertRequest.class);
          CertWithRevocationInfo cert;
          if (req.getCaName() != null) {
            cert = caManager.getCert(req.getCaName(), req.getSerialNumber());
          } else {
            X500Name issuer = X500Name.getInstance(req.getEncodedIssuerDn());
            cert = caManager.getCert(issuer, req.getSerialNumber());
          }

          resp = new GetCertResponse(new CertWithRevocationInfoWrapper(cert));
          break;
        }
        case getCertprofile: {
          String name = getNameFromRequest(in);
          CertprofileEntry result = caManager.getCertprofile(name);
          resp = new GetCertprofileResponse(result);
          break;
        }
        case getCertprofileNames: {
          Set<String> result = caManager.getCertprofileNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getCertprofilesForCa: {
          String caName = getNameFromRequest(in);
          caManager.getCertprofilesForCa(caName);
          break;
        }
        case getCertRequest: {
          GetCertRequestRequest req = parse(in, GetCertRequestRequest.class);
          byte[] result = caManager.getCertRequest(req.getCaName(), req.getSerialNumber());
          resp = new ByteArrayResponse(result);
          break;
        }
        case getCrl: {
          GetCrlRequest req = parse(in, GetCrlRequest.class);
          X509CRL crl = caManager.getCrl(req.getCaName(), req.getCrlNumber());
          resp = toByteArrayResponse(action, crl);
          break;
        }
        case getCurrentCrl: {
          String caName = getNameFromRequest(in);
          X509CRL crl = caManager.getCurrentCrl(caName);
          resp = toByteArrayResponse(action, crl);
          break;
        }
        case getFailedCaNames: {
          Set<String> result = caManager.getFailedCaNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getInactiveCaNames: {
          Set<String> result = caManager.getInactiveCaNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getPublisher: {
          String name = getNameFromRequest(in);
          PublisherEntry result = caManager.getPublisher(name);
          resp = new GetPublisherResponse(result);
          break;
        }
        case getPublisherNames: {
          Set<String> result = caManager.getPublisherNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getPublishersForCa: {
          String caName = getNameFromRequest(in);
          List<PublisherEntry> result = caManager.getPublishersForCa(caName);
          resp = new GetPublischersForCaResponse(result);
          break;
        }
        case getRequestor: {
          String name = getNameFromRequest(in);
          RequestorEntry result = caManager.getRequestor(name);
          resp = new GetRequestorResponse(result);
          break;
        }
        case getRequestorNames: {
          Set<String> result = caManager.getRequestorNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getRequestorsForCa: {
          String caName = getNameFromRequest(in);
          Set<CaHasRequestorEntry> result = caManager.getRequestorsForCa(caName);
          resp = new GetRequestorsForCaResponse(result);
          break;
        }
        case getSigner: {
          String name = getNameFromRequest(in);
          SignerEntry result = caManager.getSigner(name);
          resp = new GetSignerResponse(new SignerEntryWrapper(result));
          break;
        }
        case getSignerNames: {
          Set<String> result = caManager.getSignerNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getSuccessfulCaNames: {
          Set<String> result = caManager.getSuccessfulCaNames();
          resp = new StringSetResponse(result);
          break;
        }
        case getSupportedCertprofileTypes: {
          Set<String> result = caManager.getSupportedCertprofileTypes();
          resp = new StringSetResponse(result);
          break;
        }
        case getSupportedPublisherTypes: {
          Set<String> result = caManager.getSupportedPublisherTypes();
          resp = new StringSetResponse(result);
          break;
        }
        case getSupportedSignerTypes: {
          Set<String> result = caManager.getSupportedSignerTypes();
          resp = new StringSetResponse(result);
          break;
        }
        case getUser: {
          String name = getNameFromRequest(in);
          UserEntry result = caManager.getUser(name);
          resp = new GetUserResponse(result);
          break;
        }
        case listCertificates: {
          ListCertificatesRequest req = parse(in, ListCertificatesRequest.class);
          X500Name subjectPattern = X500Name.getInstance(req.getEncodedSubjectDnPattern());
          List<CertListInfo> result = caManager.listCertificates(req.getCaName(), subjectPattern,
              req.getValidFrom(), req.getValidTo(), req.getOrderBy(), req.getNumEntries());
          resp = new ListCertificatesResponse(result);
          break;
        }
        case loadConf: {
          LoadConfRequest req = parse(in, LoadConfRequest.class);
          Map<String, X509Certificate> rootcaNameCertMap =
              caManager.loadConf(new ByteArrayInputStream(req.getConfBytes()));

          if (rootcaNameCertMap == null || rootcaNameCertMap.isEmpty()) {
            resp = new LoadConfResponse(null);
          } else {
            Map<String, byte[]> result = new HashMap<>(rootcaNameCertMap.size());
            for (String name : result.keySet()) {
              byte[] encodedCert;
              try {
                encodedCert = rootcaNameCertMap.get(name).getEncoded();
              } catch (CertificateEncodingException ex) {
                final String errMsg =
                    "could not encode newly generated certificate of root CA " + name;
                LOG.warn(errMsg);
                throw new MyException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, errMsg);
              }
              result.put(name, encodedCert);
            }
            resp = new LoadConfResponse(result);
          }

          break;
        }
        case notifyCaChange: {
          caManager.notifyCaChange();
          break;
        }
        case removeCa: {
          String name = getNameFromRequest(in);
          caManager.removeCa(name);
          break;
        }
        case removeCaAlias: {
          String name = getNameFromRequest(in);
          caManager.removeCaAlias(name);
          break;
        }
        case removeCertificate: {
          RemoveCertificateRequest req = parse(in, RemoveCertificateRequest.class);
          caManager.removeCertificate(req.getCaName(), req.getSerialNumber());
          break;
        }
        case removeCertprofile: {
          String name = getNameFromRequest(in);
          caManager.removeCertprofile(name);
          break;
        }
        case removeCertprofileFromCa: {
          RemoveEntityFromCaRequest req = parse(in, RemoveEntityFromCaRequest.class);
          caManager.removeCertprofileFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removePublisher: {
          String name = getNameFromRequest(in);
          caManager.removePublisher(name);
          break;
        }
        case removePublisherFromCa: {
          RemoveEntityFromCaRequest req = parse(in, RemoveEntityFromCaRequest.class);
          caManager.removePublisherFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removeRequestor: {
          String name = getNameFromRequest(in);
          caManager.removeRequestor(name);
          break;
        }
        case removeRequestorFromCa: {
          RemoveEntityFromCaRequest req = parse(in, RemoveEntityFromCaRequest.class);
          caManager.removeRequestorFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removeSigner: {
          String name = getNameFromRequest(in);
          caManager.removeSigner(name);
          break;
        }
        case removeUser: {
          String name = getNameFromRequest(in);
          caManager.removeUser(name);
          break;
        }
        case removeUserFromCa: {
          RemoveEntityFromCaRequest req = parse(in, RemoveEntityFromCaRequest.class);
          caManager.removeUserFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case republishCertificates: {
          RepublishCertificatesRequest req = parse(in, RepublishCertificatesRequest.class);
          caManager.republishCertificates(req.getCaName(), req.getPublisherNames(),
              req.getNumThreads());
          break;
        }
        case restartCaSystem: {
          caManager.restartCaSystem();
          break;
        }
        case revokeCa: {
          RevokeCaRequest req = parse(in, RevokeCaRequest.class);
          caManager.revokeCa(req.getCaName(), req.getRevocationInfo());
          break;
        }
        case revokeCertficate: {
          RevokeCertificateRequest req = parse(in, RevokeCertificateRequest.class);
          caManager.revokeCertificate(req.getCaName(),req.getSerialNumber(),
              req.getReason(), req.getInvalidityTime());
          break;
        }
        case unlockCa: {
          caManager.unlockCa();
          break;
        }
        case unrevokeCa: {
          String name = getNameFromRequest(in);
          caManager.unrevokeCa(name);
          break;
        }
        case unrevokeCertificate: {
          UnrevokeCertificateRequest req = parse(in, UnrevokeCertificateRequest.class);
          caManager.unrevokeCertificate(req.getCaName(), req.getSerialNumber());
          break;
        }
        default: {
          throw new MyException(HttpServletResponse.SC_NOT_FOUND,
              "unsupported action " + actionStr);
        }
      }

      response.setContentType(CT_RESPONSE);
      if (resp == null) {
        response.setContentLength(0);
      } else {
        byte[] respBytes = JSON.toJSONBytes(resp);
        response.setContentLength(respBytes.length);
        response.getOutputStream().write(respBytes);
      }
    } catch (MyException ex) {
      writeErrorMessage(response, ex.getMessage());
      response.setStatus(ex.getStatus());
    } catch (CaMgmtException ex) {
      LOG.error("CaMgmtException", ex);
      writeErrorMessage(response, ex.getMessage());
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      response.flushBuffer();
    }
  } // method service

  private static void writeErrorMessage(HttpServletResponse resp, String message)
      throws IOException {
    ErrorResponse errResp = new ErrorResponse(message);
    byte[] errRespBytes = JSON.toJSONBytes(errResp);

    resp.setContentType(CT_RESPONSE);
    resp.setContentLength(errRespBytes.length);
    resp.getOutputStream().write(errRespBytes);
  }

  private static ByteArrayResponse toByteArrayResponse(CommAction action, X509Certificate cert)
      throws MyException {
    if (cert == null) {
      return new ByteArrayResponse(null);
    }

    byte[] encoded;
    try {
      encoded = cert.getEncoded();
    } catch (CertificateEncodingException ex) {
      LOG.warn(action + ": could not encode the generated certificate", ex);
      throw new MyException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "could not encode the generated certificate");
    }

    return new ByteArrayResponse(encoded);
  }

  private static ByteArrayResponse toByteArrayResponse(CommAction action, X509CRL crl)
      throws MyException {
    if (crl == null) {
      return new ByteArrayResponse(null);
    }

    byte[] encoded;
    try {
      encoded = crl.getEncoded();
    } catch (CRLException ex) {
      LOG.warn(action + ": could not encode the generated CRL", ex);
      throw new MyException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "could not encode the generated CRL");
    }

    return new ByteArrayResponse(encoded);
  }

  private static String getNameFromRequest(InputStream in) throws CaMgmtException {
    NameRequest req = parse(in, NameRequest.class);
    return req.getName();
  }

  private static <T extends CommRequest> T parse(InputStream in, Class<?> clazz)
      throws CaMgmtException {
    try {
      byte[] inBytes = IoUtil.read(in);
      System.out.write(inBytes);
      return JSON.parseObject(inBytes, clazz);
    } catch (RuntimeException | IOException ex) {
      throw new CaMgmtException("cannot parse response " + clazz + " from InputStream");
    }
  }

}
