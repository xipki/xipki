// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.MgmtAction;
import org.xipki.ca.api.mgmt.MgmtRequest;
import org.xipki.ca.api.mgmt.MgmtResponse;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.security.KeyCertBytesPair;
import org.xipki.security.X509Cert;
import org.xipki.security.X509Crl;
import org.xipki.security.util.TlsHelper;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.extra.http.HttpConstants;
import org.xipki.util.extra.http.HttpResponse;
import org.xipki.util.extra.http.HttpStatusCode;
import org.xipki.util.extra.http.XiHttpRequest;
import org.xipki.util.extra.http.XiHttpResponse;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * CA management servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

class CaHttpMgmtServlet {

  private static final class MyException extends Exception {

    private final int status;

    public MyException(int status, String message) {
      super(message);
      this.status = status;
    }

    public int getStatus() {
      return status;
    }

  }

  private static final Logger LOG =
      LoggerFactory.getLogger(CaHttpMgmtServlet.class);

  private static final String CT_RESPONSE = "application/json";

  private final boolean logReqResp;

  private final Set<X509Cert> mgmtCerts;

  private final CaManager caManager;

  private final String reverseProxyMode;

  public CaHttpMgmtServlet(CaManager caManager, String reverseProxyMode,
                           Collection<X509Cert> mgmtCerts, boolean logReqResp) {
    this.caManager = Args.notNull(caManager, "caManager");
    this.reverseProxyMode = reverseProxyMode;
    this.mgmtCerts = new HashSet<>(Args.notEmpty(mgmtCerts, "mgmtCerts"));
    this.logReqResp = logReqResp;
  }

  public void service(XiHttpRequest request, XiHttpResponse response)
      throws IOException {
    String method = request.getMethod();
    if (!"POST".equalsIgnoreCase(method)) {
      response.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }

    byte[] reqBody  = null;
    byte[] respBody = null;
    String path = null;
    try {
      X509Cert clientCert = Optional.ofNullable(
          TlsHelper.getTlsClientCert(request, reverseProxyMode)).orElseThrow(
              () -> new MyException(HttpStatusCode.SC_UNAUTHORIZED,
                  "remote management is not permitted if TLS client " +
                      "certificate is not present"));

      if (!mgmtCerts.contains(clientCert)) {
        throw new MyException(HttpStatusCode.SC_UNAUTHORIZED,
            "remote management is not permitted to the client without " +
            "valid certificate");
      }

      path = (String) request.getAttribute(
          HttpConstants.ATTR_XIPKI_PATH);

      if (path == null || path.length() < 2) {
        throw new MyException(HttpStatusCode.SC_NOT_FOUND,
            "no action is specified");
      }

      String actionStr = path.substring(1);
      MgmtAction action = Optional.ofNullable(MgmtAction.ofName(actionStr))
          .orElseThrow(() -> new MyException(HttpStatusCode.SC_NOT_FOUND,
              "unknown action '" + actionStr + "'"));

      reqBody = IoUtil.readAllBytesAndClose(request.getInputStream());

      JsonMap json;
      try {
        json = (reqBody.length == 0) ? null
            : JsonParser.parseMap(reqBody, false);
      } catch (Exception e) {
        throw new MyException(HttpStatusCode.SC_BAD_REQUEST,
            "request is not well-formed json");
      }

      MgmtResponse resp = null;
      switch (action) {
        case addCa: {
          MgmtRequest.AddCa req = MgmtRequest.AddCa.parse(nonNullReq(json));
          caManager.addCa(req.getCaEntry());
          break;
        }
        case addCaAlias: {
          MgmtRequest.AddCaAlias req =
              MgmtRequest.AddCaAlias.parse(nonNullReq(json));
          caManager.addCaAlias(req.getAliasName(), req.getCaName());
          break;
        }
        case addCertprofile: {
          MgmtRequest.AddCertprofile req =
              MgmtRequest.AddCertprofile.parse(nonNullReq(json));
          caManager.addCertprofile(req.getCertprofileEntry());
          break;
        }
        case addCertprofileToCa: {
          MgmtRequest.AddCertprofileToCa req =
              MgmtRequest.AddCertprofileToCa.parse(nonNullReq(json));
          caManager.addCertprofileToCa(req.getProfileName(), req.getCaName());
          break;
        }
        case addPublisher: {
          MgmtRequest.AddPublisher req =
              MgmtRequest.AddPublisher.parse(nonNullReq(json));
          caManager.addPublisher(req.getPublisherEntry());
          break;
        }
        case addPublisherToCa: {
          MgmtRequest.AddPublisherToCa req =
              MgmtRequest.AddPublisherToCa.parse(nonNullReq(json));
          caManager.addPublisherToCa(req.getPublisherName(), req.getCaName());
          break;
        }
        case addRequestor: {
          MgmtRequest.AddRequestor req =
              MgmtRequest.AddRequestor.parse(nonNullReq(json));
          caManager.addRequestor(req.getRequestorEntry());
          break;
        }
        case addRequestorToCa: {
          MgmtRequest.AddRequestorToCa req =
              MgmtRequest.AddRequestorToCa.parse(nonNullReq(json));
          caManager.addRequestorToCa(req.getRequestor(), req.getCaName());
          break;
        }
        case addSigner: {
          MgmtRequest.AddSigner req =
              MgmtRequest.AddSigner.parse(nonNullReq(json));
          caManager.addSigner(req.getSignerEntry());
          break;
        }
        case changeCa: {
          MgmtRequest.ChangeCa req =
              MgmtRequest.ChangeCa.parse(nonNullReq(json));
          caManager.changeCa(req.getChangeCaEntry());
          break;
        }
        case changeCertprofile: {
          MgmtRequest.ChangeTypeConfEntity req =
              MgmtRequest.ChangeTypeConfEntity.parse(nonNullReq(json));
          caManager.changeCertprofile(req.getName(), req.getType(),
              req.getConf());
          break;
        }
        case changePublisher: {
          MgmtRequest.ChangeTypeConfEntity req =
              MgmtRequest.ChangeTypeConfEntity.parse(nonNullReq(json));
          caManager.changePublisher(req.getName(), req.getType(),
              req.getConf());
          break;
        }
        case changeRequestor: {
          MgmtRequest.ChangeTypeConfEntity req =
              MgmtRequest.ChangeTypeConfEntity.parse(nonNullReq(json));
          caManager.changeRequestor(req.getName(), req.getType(),
              req.getConf());
          break;
        }
        case changeSigner: {
          MgmtRequest.ChangeSigner req =
              MgmtRequest.ChangeSigner.parse(nonNullReq(json));
          caManager.changeSigner(req.getName(), req.getType(), req.getConf(),
              req.getBase64Cert());
          break;
        }
        case exportConf: {
          MgmtRequest.ExportConf req =
              MgmtRequest.ExportConf.parse(nonNullReq(json));
          InputStream confStream = caManager.exportConf(req.getCaNames());
          resp = new MgmtResponse.ByteArray(
                  IoUtil.readAllBytesAndClose(confStream));
          break;
        }
        case generateCertificate: {
          MgmtRequest.GenerateCert req =
              MgmtRequest.GenerateCert.parse(nonNullReq(json));
          X509Cert cert = caManager.generateCertificate(req.getCaName(),
              req.getProfileName(), req.getEncodedCsr(),
              req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case generateCrossCertificate: {
          MgmtRequest.GenerateCrossCertificate req =
              MgmtRequest.GenerateCrossCertificate.parse(nonNullReq(json));

          X509Cert cert = caManager.generateCrossCertificate(req.getCaName(),
              req.getProfileName(),       req.getEncodedCsr(),
              req.getEncodedTargetCert(), req.getNotBefore(),
              req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case generateKeyCert: {
          MgmtRequest.GenerateKeyCert req =
              MgmtRequest.GenerateKeyCert.parse(nonNullReq(json));
          KeyCertBytesPair keyCertBytesPair = caManager.generateKeyCert(
              req.getCaName(),  req.getProfileName(),
              req.getSubject(), req.getNotBefore(), req.getNotAfter());

          resp = new MgmtResponse.KeyCertBytes(keyCertBytesPair.getKey(),
              keyCertBytesPair.getCert());
          break;
        }
        case generateCrlOnDemand: {
          resp = toByteArray(action, caManager.generateCrlOnDemand(
              getNameFromRequest(nonNullReq(json))));
          break;
        }
        case generateRootCa: {
          MgmtRequest.GenerateRootCa req =
              MgmtRequest.GenerateRootCa.parse(nonNullReq(json));

          X509Cert cert = caManager.generateRootCa(req.getCaEntry(),
              req.getProfileName(), req.getSubject(),
              req.getSerialNumber(), req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case getAliasesForCa: {
          resp = new MgmtResponse.StringSet(
              caManager.getAliasesForCa(getNameFromRequest(nonNullReq(json))));
          break;
        }
        case getCa: {
          String name = getNameFromRequest(nonNullReq(json));
          CaEntry caEntry = Optional.ofNullable(caManager.getCa(name))
              .orElseThrow(() -> new CaMgmtException("Unknown CA " + name));
          resp = new MgmtResponse.GetCa(caEntry);
          break;
        }
        case getCaCerts: {
          String name = getNameFromRequest(nonNullReq(json));
          List<X509Cert> caCerts = Optional.ofNullable(
              caManager.getCaCerts(name)).orElseThrow(
                  () -> new CaMgmtException("Unknown CA " + name));
          resp = new MgmtResponse.StringResponse(
              X509Util.encodeCertificates(caCerts.toArray(new X509Cert[0])));
          break;
        }
        case getCaAliasNames: {
          resp = new MgmtResponse.StringSet(caManager.getCaAliasNames());
          break;
        }
        case getCaNameForAlias: {
          String aliasName = getNameFromRequest(nonNullReq(json));
          resp = new MgmtResponse.StringResponse(
              caManager.getCaNameForAlias(aliasName));
          break;
        }
        case getCaNames: {
          resp = new MgmtResponse.StringSet(caManager.getCaNames());
          break;
        }
        case getCaSystemStatus: {
          resp = new MgmtResponse.GetCaSystemStatus(
              caManager.getCaSystemStatus());
          break;
        }
        case getCert: {
          MgmtRequest.GetCert req = MgmtRequest.GetCert.parse(nonNullReq(json));

          CertWithRevocationInfo cert;
          if (req.getCaName() != null) {
            cert = caManager.getCert(req.getCaName(), req.getSerialNumber());
          } else {
            X500Name issuer = X500Name.getInstance(req.getEncodedIssuerDn());
            cert = caManager.getCert(issuer, req.getSerialNumber());
          }

          if (cert != null) {
            resp = new MgmtResponse.GetCert(cert.getCert().getCert(),
                null, null);
          } else {
            resp = new MgmtResponse.GetCert(null, null, null);
          }
          break;
        }
        case getCertprofile: {
          String name = getNameFromRequest(nonNullReq(json));
          CertprofileEntry result = Optional.ofNullable(
              caManager.getCertprofile(name)).orElseThrow(
                  () -> new CaMgmtException("Unknown Certprofile " + name));
          resp = new MgmtResponse.GetCertprofile(result);
          break;
        }
        case getCertprofileNames: {
          resp = new MgmtResponse.StringSet(caManager.getCertprofileNames());
          break;
        }
        case getCertprofilesForCa: {
          Set<CaProfileEntry> list = caManager.getCertprofilesForCa(
              getNameFromRequest(nonNullReq(json)));
          Set<String> strList = new HashSet<>();
          for (CaProfileEntry entry : list) {
            strList.add(entry.getEncoded());
          }
          resp = new MgmtResponse.StringSet(strList);
          break;
        }
        case getCrl: {
          MgmtRequest.GetCrl req = MgmtRequest.GetCrl.parse(nonNullReq(json));
          X509Crl crl = Optional.ofNullable(
              caManager.getCrl(req.getCaName(), req.getCrlNumber()))
              .orElseThrow(() -> new CaMgmtException(
                  "Found no CRL for CA " + req.getCaName() +
                  " with CRL number 0x" + req.getCrlNumber().toString(16)));
          resp = toByteArray(action, crl);
          break;
        }
        case getCurrentCrl: {
          String caName = getNameFromRequest(nonNullReq(json));
          X509Crl crl = Optional.ofNullable(
              caManager.getCurrentCrl(caName)).orElseThrow(
                  () -> new CaMgmtException("No current CRL for CA " + caName));
          resp = toByteArray(action, crl);
          break;
        }
        case getFailedCaNames: {
          resp = new MgmtResponse.StringSet(caManager.getFailedCaNames());
          break;
        }
        case getInactiveCaNames: {
          resp = new MgmtResponse.StringSet(caManager.getInactiveCaNames());
          break;
        }
        case getPublisher: {
          String name = getNameFromRequest(nonNullReq(json));
          PublisherEntry result = Optional.ofNullable(
              caManager.getPublisher(name)).orElseThrow(
                  () -> new CaMgmtException("Unknown publisher " + name));
          resp = new MgmtResponse.GetPublisher(result);
          break;
        }
        case getPublisherNames: {
          resp = new MgmtResponse.StringSet(caManager.getPublisherNames());
          break;
        }
        case getPublisherNamesForCa: {
          resp = new MgmtResponse.StringSet(caManager.getPublisherNamesForCa(
              getNameFromRequest(nonNullReq(json))));
          break;
        }
        case getRequestor: {
          String name = getNameFromRequest(nonNullReq(json));
          RequestorEntry result = Optional.ofNullable(
              caManager.getRequestor(name)).orElseThrow(
                  () -> new CaMgmtException("Unknown requestor " + name));
          resp = new MgmtResponse.GetRequestor(result);
          break;
        }
        case getRequestorNames: {
          resp = new MgmtResponse.StringSet(caManager.getRequestorNames());
          break;
        }
        case getRequestorsForCa: {
          resp = new MgmtResponse.GetRequestorsForCa(
              caManager.getRequestorsForCa(
                  getNameFromRequest(nonNullReq(json))));
          break;
        }
        case getSigner: {
          String name = getNameFromRequest(nonNullReq(json));
          SignerEntry result = Optional.ofNullable(
              caManager.getSigner(name)).orElseThrow(
                  () -> new CaMgmtException("Unknown signer " + name));
          resp = new MgmtResponse.GetSigner(result);
          break;
        }
        case getSignerNames: {
          resp = new MgmtResponse.StringSet(caManager.getSignerNames());
          break;
        }
        case getSuccessfulCaNames: {
          resp = new MgmtResponse.StringSet(caManager.getSuccessfulCaNames());
          break;
        }
        case getSupportedCertprofileTypes: {
          resp = new MgmtResponse.StringSet(
              caManager.getSupportedCertprofileTypes());
          break;
        }
        case getSupportedPublisherTypes: {
          resp = new MgmtResponse.StringSet(
              caManager.getSupportedPublisherTypes());
          break;
        }
        case getSupportedSignerTypes: {
          resp = new MgmtResponse.StringSet(
              caManager.getSupportedSignerTypes());
          break;
        }
        case listCertificates: {
          MgmtRequest.ListCertificates req =
              MgmtRequest.ListCertificates.parse(nonNullReq(json));
          X500Name subjectPattern =
              X500Name.getInstance(req.getEncodedSubjectDnPattern());
          List<CertListInfo> result = caManager.listCertificates(
              req.getCaName(), subjectPattern, req.getValidFrom(),
              req.getValidTo(), req.getOrderBy(), req.getNumEntries());
          resp = new MgmtResponse.ListCertificates(result);
          break;
        }
        case loadConf: {
          MgmtRequest.LoadConf req =
              MgmtRequest.LoadConf.parse(nonNullReq(json));
          caManager.loadConf(req.getConfBytes());
          break;
        }
        case notifyCaChange: {
          caManager.notifyCaChange();
          break;
        }
        case removeCa: {
          caManager.removeCa(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case removeCaAlias: {
          caManager.removeCaAlias(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case removeCertificate: {
          MgmtRequest.RemoveCertificate req =
              MgmtRequest.RemoveCertificate.parse(nonNullReq(json));
          caManager.removeCertificate(req.getCaName(), req.getSerialNumber());
          break;
        }
        case removeCertprofile: {
          caManager.removeCertprofile(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case removeCertprofileFromCa: {
          MgmtRequest.RemoveEntityFromCa req =
              MgmtRequest.RemoveEntityFromCa.parse(nonNullReq(json));
          caManager.removeCertprofileFromCa(
              req.getEntityName(), req.getCaName());
          break;
        }
        case removePublisher: {
          caManager.removePublisher(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case removePublisherFromCa: {
          MgmtRequest.RemoveEntityFromCa req =
              MgmtRequest.RemoveEntityFromCa.parse(nonNullReq(json));
          caManager.removePublisherFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removeRequestor: {
          caManager.removeRequestor(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case removeRequestorFromCa: {
          MgmtRequest.RemoveEntityFromCa req =
              MgmtRequest.RemoveEntityFromCa.parse(nonNullReq(json));
          caManager.removeRequestorFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removeSigner: {
          caManager.removeSigner(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case republishCertificates: {
          MgmtRequest.RepublishCertificates req =
              MgmtRequest.RepublishCertificates.parse(nonNullReq(json));
          caManager.republishCertificates(req.getCaName(),
              req.getPublisherNames(), req.getNumThreads());
          break;
        }
        case restartCa: {
          caManager.restartCa(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case restartCaSystem: {
          caManager.restartCaSystem();
          break;
        }
        case revokeCa: {
          MgmtRequest.RevokeCa req =
              MgmtRequest.RevokeCa.parse(nonNullReq(json));
          caManager.revokeCa(req.getCaName(), req.getRevocationInfo());
          break;
        }
        case revokeCertificate: {
          MgmtRequest.RevokeCertificate req =
              MgmtRequest.RevokeCertificate.parse(nonNullReq(json));
          caManager.revokeCertificate(req.getCaName(), req.getSerialNumber(),
              req.getReason(), req.getInvalidityTime());
          break;
        }
        case tokenInfoP11: {
          MgmtRequest.TokenInfoP11 req =
              MgmtRequest.TokenInfoP11.parse(nonNullReq(json));
          String info = caManager.getTokenInfoP11(
              req.getModuleName(), req.getSlotIndex(), req.isVerbose());
          resp = new MgmtResponse.StringResponse(info);
          break;
        }
        case unlockCa: {
          caManager.unlockCa();
          break;
        }
        case unrevokeCa: {
          caManager.unrevokeCa(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case unsuspendCertificate: {
          MgmtRequest.UnsuspendCertificate req =
              MgmtRequest.UnsuspendCertificate.parse(nonNullReq(json));
          caManager.unsuspendCertificate(req.getCaName(),
              req.getSerialNumber());
          break;
        }
        case addDbSchema: {
          MgmtRequest.AddOrChangeDbSchema req =
              MgmtRequest.AddOrChangeDbSchema.parse(nonNullReq(json));
          caManager.addDbSchema(req.getName(), req.getValue());
          break;
        }
        case changeDbSchema: {
          MgmtRequest.AddOrChangeDbSchema req =
              MgmtRequest.AddOrChangeDbSchema.parse(nonNullReq(json));
          caManager.changeDbSchema(req.getName(), req.getValue());
          break;
        }
        case removeDbSchema: {
          caManager.removeDbSchema(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case getDbSchemas: {
          resp = new MgmtResponse.GetDbSchemas(caManager.getDbSchemas());
          break;
        }
        case addKeypairGen: {
          MgmtRequest.AddKeypairGen req =
              MgmtRequest.AddKeypairGen.parse(nonNullReq(json));
          caManager.addKeypairGen(req.getEntry());
          break;
        }
        case changeKeypairGen: {
          MgmtRequest.ChangeTypeConfEntity req =
              MgmtRequest.ChangeTypeConfEntity.parse(nonNullReq(json));
          caManager.changeKeypairGen(req.getName(), req.getType(),
              req.getConf());
          break;
        }
        case removeKeypairGen: {
          caManager.removeKeypairGen(getNameFromRequest(nonNullReq(json)));
          break;
        }
        case getKeypairGenNames: {
          resp = new MgmtResponse.StringSet(caManager.getKeypairGenNames());
          break;
        }
        case getKeypairGen: {
          String name = getNameFromRequest(nonNullReq(json));
          KeypairGenEntry result = Optional.ofNullable(
              caManager.getKeypairGen(name)).orElseThrow(
                  () -> new CaMgmtException("Unknown KeypairGen " + name));
          resp = new MgmtResponse.GetKeypairGen(result);
          break;
        }
        default: {
          throw new MyException(HttpStatusCode.SC_NOT_FOUND,
              "unsupported action " + actionStr);
        }
      }

      respBody = (resp == null) ? new byte[0] : resp.getEncoded();
      new HttpResponse(HttpStatusCode.SC_OK, CT_RESPONSE, null, respBody)
          .fillResponse(response);
    } catch (MyException ex) {
      Map<String, String> headers = Collections.singletonMap(
          HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());

      new HttpResponse(ex.getStatus(), null, headers, null)
          .fillResponse(response);
    } catch (CaMgmtException | CodecException ex) {
      LOG.error("CaMgmtException", ex);
      Map<String, String> headers = Collections.singletonMap(
          HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());

      new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR,
          null, headers, null).fillResponse(response);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR)
          .fillResponse(response);
    } finally {
      if (logReqResp && LOG.isDebugEnabled()) {
        String reqBodyStr = reqBody == null ? null
            : Base64.encodeToString( reqBody, true);
        String respBodyStr = respBody == null ? null
            : Base64.encodeToString(respBody, true);
        LOG.debug("HTTP CA-MGMT path: {}\nRequest:\n{}\nResponse:\n{}",
            path, reqBodyStr, respBodyStr);
      }
    }
  } // method doPost

  private static JsonMap nonNullReq(JsonMap req) throws MyException {
    if (req == null) {
      throw new MyException(HttpStatusCode.SC_BAD_REQUEST,
          "request body is empty");
    }
    return req;
  }

  private static MgmtResponse.ByteArray toByteArray(X509Cert cert) {
    if (cert == null) {
      return new MgmtResponse.ByteArray(null);
    }

    byte[] encoded = cert.getEncoded();
    return new MgmtResponse.ByteArray(encoded);
  } // method toByteArray

  private static MgmtResponse.ByteArray toByteArray(
      MgmtAction action, X509Crl crl)
      throws MyException {
    if (crl == null) {
      return new MgmtResponse.ByteArray(null);
    }

    return new MgmtResponse.ByteArray(crl.getEncoded());
  } // method toByteArray

  /**
   * The specified stream is closed after this method call.
   */
  private static String getNameFromRequest(JsonMap json)
      throws CodecException {
    MgmtRequest.Name req = MgmtRequest.Name.parse(json);
    return req.getName();
  } // method getNameFromRequest

}
