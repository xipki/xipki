// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaJson;
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
import org.xipki.security.util.TlsHelper;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

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

  private static final Logger LOG = LoggerFactory.getLogger(CaHttpMgmtServlet.class);

  private static final String CT_RESPONSE = "application/json";

  private final Set<X509Cert> mgmtCerts;

  private final CaManager caManager;

  private final String reverseProxyMode;

  public CaHttpMgmtServlet(CaManager caManager, String reverseProxyMode, Collection<X509Cert> mgmtCerts) {
    this.caManager = Args.notNull(caManager, "caManager");
    this.reverseProxyMode = reverseProxyMode;
    this.mgmtCerts = new HashSet<>(Args.notEmpty(mgmtCerts, "mgmtCerts"));
  }

  public void service(XiHttpRequest request, XiHttpResponse response) throws IOException {
    String method = request.getMethod();
    if (!"POST".equalsIgnoreCase(method)) {
      response.setStatus(HttpStatusCode.SC_METHOD_NOT_ALLOWED);
    }

    try {
      X509Cert clientCert = Optional.ofNullable(TlsHelper.getTlsClientCert(request, reverseProxyMode))
          .orElseThrow(() -> new MyException(HttpStatusCode.SC_UNAUTHORIZED,
            "remote management is not permitted if TLS client certificate is not present"));

      if (!mgmtCerts.contains(clientCert)) {
        throw new MyException(HttpStatusCode.SC_UNAUTHORIZED,
            "remote management is not permitted to the client without valid certificate");
      }

      String path = (String) request.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

      if (path == null || path.length() < 2) {
        throw new MyException(HttpStatusCode.SC_NOT_FOUND, "no action is specified");
      }

      String actionStr = path.substring(1);
      MgmtAction action = Optional.ofNullable(MgmtAction.ofName(actionStr)).orElseThrow(
          () -> new MyException(HttpStatusCode.SC_NOT_FOUND, "unknown action '" + actionStr + "'"));

      MgmtResponse resp = null;

      InputStream requestStream = request.getInputStream();

      switch (action) {
        case addCa: {
          MgmtRequest.AddCa req = parse(requestStream, MgmtRequest.AddCa.class);
          caManager.addCa(req.getCaEntry());
          break;
        }
        case addCaAlias: {
          MgmtRequest.AddCaAlias req = parse(requestStream, MgmtRequest.AddCaAlias.class);
          caManager.addCaAlias(req.getAliasName(), req.getCaName());
          break;
        }
        case addCertprofile: {
          MgmtRequest.AddCertprofile req = parse(requestStream, MgmtRequest.AddCertprofile.class);
          caManager.addCertprofile(req.getCertprofileEntry());
          break;
        }
        case addCertprofileToCa: {
          MgmtRequest.AddCertprofileToCa req = parse(requestStream, MgmtRequest.AddCertprofileToCa.class);
          caManager.addCertprofileToCa(req.getProfileName(), req.getCaName());
          break;
        }
        case addPublisher: {
          MgmtRequest.AddPublisher req = parse(requestStream, MgmtRequest.AddPublisher.class);
          caManager.addPublisher(req.getPublisherEntry());
          break;
        }
        case addPublisherToCa: {
          MgmtRequest.AddPublisherToCa req = parse(requestStream, MgmtRequest.AddPublisherToCa.class);
          caManager.addPublisherToCa(req.getPublisherName(), req.getCaName());
          break;
        }
        case addRequestor: {
          MgmtRequest.AddRequestor req = parse(requestStream, MgmtRequest.AddRequestor.class);
          caManager.addRequestor(req.getRequestorEntry());
          break;
        }
        case addRequestorToCa: {
          MgmtRequest.AddRequestorToCa req = parse(requestStream, MgmtRequest.AddRequestorToCa.class);
          caManager.addRequestorToCa(req.getRequestor(), req.getCaName());
          break;
        }
        case addSigner: {
          MgmtRequest.AddSigner req = parse(requestStream, MgmtRequest.AddSigner.class);
          caManager.addSigner(req.getSignerEntry());
          break;
        }
        case changeCa: {
          MgmtRequest.ChangeCa req = parse(requestStream, MgmtRequest.ChangeCa.class);
          caManager.changeCa(req.getChangeCaEntry());
          break;
        }
        case changeCertprofile: {
          MgmtRequest.ChangeTypeConfEntity req = parse(requestStream, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changeCertprofile(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changePublisher: {
          MgmtRequest.ChangeTypeConfEntity req = parse(requestStream, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changePublisher(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changeRequestor: {
          MgmtRequest.ChangeTypeConfEntity req = parse(requestStream, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changeRequestor(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changeSigner: {
          MgmtRequest.ChangeSigner req = parse(requestStream, MgmtRequest.ChangeSigner.class);
          caManager.changeSigner(req.getName(), req.getType(), req.getConf(), req.getBase64Cert());
          break;
        }
        case exportConf: {
          MgmtRequest.ExportConf req = parse(requestStream, MgmtRequest.ExportConf.class);
          InputStream confStream = caManager.exportConf(req.getCaNames());
          resp = new MgmtResponse.ByteArray(IoUtil.readAllBytesAndClose(confStream));
          break;
        }
        case generateCertificate: {
          MgmtRequest.GenerateCert req = parse(requestStream, MgmtRequest.GenerateCert.class);
          X509Cert cert = caManager.generateCertificate(req.getCaName(), req.getProfileName(),
              req.getEncodedCsr(), req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case generateCrossCertificate: {
          MgmtRequest.GenerateCrossCertificate req = parse(requestStream, MgmtRequest.GenerateCrossCertificate.class);
          X509Cert cert = caManager.generateCrossCertificate(req.getCaName(), req.getProfileName(),
              req.getEncodedCsr(), req.getEncodedTargetCert(),
              req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case generateKeyCert: {
          MgmtRequest.GenerateKeyCert req = parse(requestStream, MgmtRequest.GenerateKeyCert.class);
          KeyCertBytesPair keyCertBytesPair = caManager.generateKeyCert(req.getCaName(), req.getProfileName(),
              req.getSubject(), req.getNotBefore(), req.getNotAfter());
          resp = new MgmtResponse.KeyCertBytes(keyCertBytesPair.getKey(), keyCertBytesPair.getCert());
          break;
        }
        case generateCrlOnDemand: {
          resp = toByteArray(action, caManager.generateCrlOnDemand(getNameFromRequest(requestStream)));
          break;
        }
        case generateRootCa: {
          MgmtRequest.GenerateRootCa req = parse(requestStream, MgmtRequest.GenerateRootCa.class);

          X509Cert cert = caManager.generateRootCa(req.getCaEntry(), req.getCertprofileName(), req.getSubject(),
              req.getSerialNumber(), req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case getAliasesForCa: {
          resp = new MgmtResponse.StringSet(caManager.getAliasesForCa(getNameFromRequest(requestStream)));
          break;
        }
        case getCa: {
          String name = getNameFromRequest(requestStream);
          CaEntry caEntry = Optional.ofNullable(caManager.getCa(name)).orElseThrow(
              () -> new CaMgmtException("Unknown CA " + name));
          resp = new MgmtResponse.GetCa(caEntry);
          break;
        }
        case getCaCerts: {
          String name = getNameFromRequest(requestStream);
          List<X509Cert> caCerts = Optional.ofNullable(caManager.getCaCerts(name)).orElseThrow(
              () -> new CaMgmtException("Unknown CA " + name));
          resp = new MgmtResponse.StringResponse(X509Util.encodeCertificates(caCerts.toArray(new X509Cert[0])));
          break;
        }
        case getCaAliasNames: {
          resp = new MgmtResponse.StringSet(caManager.getCaAliasNames());
          break;
        }
        case getCaNameForAlias: {
          String aliasName = getNameFromRequest(requestStream);
          resp = new MgmtResponse.StringResponse(caManager.getCaNameForAlias(aliasName));
          break;
        }
        case getCaNames: {
          resp = new MgmtResponse.StringSet(caManager.getCaNames());
          break;
        }
        case getCaSystemStatus: {
          resp = new MgmtResponse.GetCaSystemStatus(caManager.getCaSystemStatus());
          break;
        }
        case getCert: {
          MgmtRequest.GetCert req = parse(requestStream, MgmtRequest.GetCert.class);
          CertWithRevocationInfo cert;
          if (req.getCaName() != null) {
            cert = caManager.getCert(req.getCaName(), req.getSerialNumber());
          } else {
            X500Name issuer = X500Name.getInstance(req.getEncodedIssuerDn());
            cert = caManager.getCert(issuer, req.getSerialNumber());
          }

          if (cert != null) {
            resp = new MgmtResponse.GetCert(new MgmtResponse.CertWithRevocationInfoWrapper(cert));
          } else {
            resp = new MgmtResponse.GetCert(null);
          }
          break;
        }
        case getCertprofile: {
          String name = getNameFromRequest(requestStream);
          CertprofileEntry result = Optional.ofNullable(caManager.getCertprofile(name))
              .orElseThrow(() -> new CaMgmtException("Unknown Certprofile " + name));
          resp = new MgmtResponse.GetCertprofile(result);
          break;
        }
        case getCertprofileNames: {
          resp = new MgmtResponse.StringSet(caManager.getCertprofileNames());
          break;
        }
        case getCertprofilesForCa: {
          Set<CaProfileEntry> list = caManager.getCertprofilesForCa(getNameFromRequest(requestStream));
          Set<String> strList = new HashSet<>();
          for (CaProfileEntry entry : list) {
            strList.add(entry.getEncoded());
          }
          resp = new MgmtResponse.StringSet(strList);
          break;
        }
        case getCrl: {
          MgmtRequest.GetCrl req = parse(requestStream, MgmtRequest.GetCrl.class);
          X509CRLHolder crl = Optional.ofNullable(caManager.getCrl(req.getCaName(), req.getCrlNumber()))
              .orElseThrow(() -> new CaMgmtException("Found no CRL for CA " + req.getCaName()
                        + " with CRL number 0x" + req.getCrlNumber().toString(16)));
          resp = toByteArray(action, crl);
          break;
        }
        case getCurrentCrl: {
          String caName = getNameFromRequest(requestStream);
          X509CRLHolder crl = Optional.ofNullable(caManager.getCurrentCrl(caName)).orElseThrow(
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
          String name = getNameFromRequest(requestStream);
          PublisherEntry result = Optional.ofNullable(caManager.getPublisher(name)).orElseThrow(
              () -> new CaMgmtException("Unknown publisher " + name));
          resp = new MgmtResponse.GetPublisher(result);
          break;
        }
        case getPublisherNames: {
          resp = new MgmtResponse.StringSet(caManager.getPublisherNames());
          break;
        }
        case getPublisherNamesForCa: {
          resp = new MgmtResponse.StringSet(caManager.getPublisherNamesForCa(getNameFromRequest(requestStream)));
          break;
        }
        case getPublishersForCa: {
          resp = new MgmtResponse.GetPublischersForCa(caManager.getPublishersForCa(getNameFromRequest(requestStream)));
          break;
        }
        case getRequestor: {
          String name = getNameFromRequest(requestStream);
          RequestorEntry result = Optional.ofNullable(caManager.getRequestor(name))
              .orElseThrow(() -> new CaMgmtException("Unknown requestor " + name));
          resp = new MgmtResponse.GetRequestor(result);
          break;
        }
        case getRequestorNames: {
          resp = new MgmtResponse.StringSet(caManager.getRequestorNames());
          break;
        }
        case getRequestorsForCa: {
          resp = new MgmtResponse.GetRequestorsForCa(caManager.getRequestorsForCa(getNameFromRequest(requestStream)));
          break;
        }
        case getSigner: {
          String name = getNameFromRequest(requestStream);
          SignerEntry result = Optional.ofNullable(caManager.getSigner(name)).orElseThrow(
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
          resp = new MgmtResponse.StringSet(caManager.getSupportedCertprofileTypes());
          break;
        }
        case getSupportedPublisherTypes: {
          resp = new MgmtResponse.StringSet(caManager.getSupportedPublisherTypes());
          break;
        }
        case getSupportedSignerTypes: {
          resp = new MgmtResponse.StringSet(caManager.getSupportedSignerTypes());
          break;
        }
        case listCertificates: {
          MgmtRequest.ListCertificates req = parse(requestStream, MgmtRequest.ListCertificates.class);
          X500Name subjectPattern = X500Name.getInstance(req.getEncodedSubjectDnPattern());
          List<CertListInfo> result = caManager.listCertificates(req.getCaName(), subjectPattern,
              req.getValidFrom(), req.getValidTo(), req.getOrderBy(), req.getNumEntries());
          resp = new MgmtResponse.ListCertificates(result);
          break;
        }
        case loadConf: {
          MgmtRequest.LoadConf req = parse2(requestStream, MgmtRequest.LoadConf.class);
          caManager.loadConf(req.getConfBytes());
          break;
        }
        case notifyCaChange: {
          caManager.notifyCaChange();
          break;
        }
        case removeCa: {
          caManager.removeCa(getNameFromRequest(requestStream));
          break;
        }
        case removeCaAlias: {
          caManager.removeCaAlias(getNameFromRequest(requestStream));
          break;
        }
        case removeCertificate: {
          MgmtRequest.RemoveCertificate req = parse(requestStream, MgmtRequest.RemoveCertificate.class);
          caManager.removeCertificate(req.getCaName(), req.getSerialNumber());
          break;
        }
        case removeCertprofile: {
          caManager.removeCertprofile(getNameFromRequest(requestStream));
          break;
        }
        case removeCertprofileFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(requestStream, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removeCertprofileFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removePublisher: {
          caManager.removePublisher(getNameFromRequest(requestStream));
          break;
        }
        case removePublisherFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(requestStream, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removePublisherFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removeRequestor: {
          caManager.removeRequestor(getNameFromRequest(requestStream));
          break;
        }
        case removeRequestorFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(requestStream, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removeRequestorFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removeSigner: {
          caManager.removeSigner(getNameFromRequest(requestStream));
          break;
        }
        case republishCertificates: {
          MgmtRequest.RepublishCertificates req = parse(requestStream, MgmtRequest.RepublishCertificates.class);
          caManager.republishCertificates(req.getCaName(), req.getPublisherNames(), req.getNumThreads());
          break;
        }
        case restartCa: {
          caManager.restartCa(getNameFromRequest(requestStream));
          break;
        }
        case restartCaSystem: {
          caManager.restartCaSystem();
          break;
        }
        case revokeCa: {
          MgmtRequest.RevokeCa req = parse(requestStream, MgmtRequest.RevokeCa.class);
          caManager.revokeCa(req.getCaName(), req.getRevocationInfo());
          break;
        }
        case revokeCertficate:
        case revokeCertificate: {
          MgmtRequest.RevokeCertificate req = parse(requestStream, MgmtRequest.RevokeCertificate.class);
          caManager.revokeCertificate(req.getCaName(), req.getSerialNumber(), req.getReason(),
              req.getInvalidityTime());
          break;
        }
        case unlockCa: {
          caManager.unlockCa();
          break;
        }
        case unrevokeCa: {
          caManager.unrevokeCa(getNameFromRequest(requestStream));
          break;
        }
        case unsuspendCertificate: {
          MgmtRequest.UnsuspendCertificate req = parse(requestStream, MgmtRequest.UnsuspendCertificate.class);
          caManager.unsuspendCertificate(req.getCaName(), req.getSerialNumber());
          break;
        }
        case addDbSchema: {
          MgmtRequest.AddOrChangeDbSchema req = parse(requestStream, MgmtRequest.AddOrChangeDbSchema.class);
          caManager.addDbSchema(req.getName(), req.getValue());
          break;
        }
        case changeDbSchema: {
          MgmtRequest.AddOrChangeDbSchema req = parse(requestStream, MgmtRequest.AddOrChangeDbSchema.class);
          caManager.changeDbSchema(req.getName(), req.getValue());
          break;
        }
        case removeDbSchema: {
          caManager.removeDbSchema(getNameFromRequest(requestStream));
          break;
        }
        case getDbSchemas: {
          resp = new MgmtResponse.GetDbSchemas(caManager.getDbSchemas());
          break;
        }
        case addKeypairGen: {
          MgmtRequest.AddKeypairGen req = parse(requestStream, MgmtRequest.AddKeypairGen.class);
          caManager.addKeypairGen(req.getEntry());
          break;
        }
        case changeKeypairGen: {
          MgmtRequest.ChangeTypeConfEntity req = parse(requestStream, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changeKeypairGen(req.getName(), req.getType(), req.getConf());
          break;
        }
        case removeKeypairGen: {
          caManager.removeKeypairGen(getNameFromRequest(requestStream));
          break;
        }
        case getKeypairGenNames: {
          resp = new MgmtResponse.StringSet(caManager.getKeypairGenNames());
          break;
        }
        case getKeypairGen: {
          String name = getNameFromRequest(requestStream);
          KeypairGenEntry result = Optional.ofNullable(caManager.getKeypairGen(name))
              .orElseThrow(() -> new CaMgmtException("Unknown KeypairGen " + name));
          resp = new MgmtResponse.GetKeypairGen(result);
          break;
        }
        default: {
          throw new MyException(HttpStatusCode.SC_NOT_FOUND, "unsupported action " + actionStr);
        }
      }

      byte[] respBytes = resp == null ? new byte[0] : CaJson.toJSONBytes(resp);
      new HttpResponse(HttpStatusCode.SC_OK, CT_RESPONSE, null, respBytes).fillResponse(response);
    } catch (MyException ex) {
      Map<String, String> headers = Collections.singletonMap(HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());
      new HttpResponse(ex.getStatus(), null, headers, null).fillResponse(response);
    } catch (CaMgmtException ex) {
      LOG.error("CaMgmtException", ex);
      Map<String, String> headers = Collections.singletonMap(HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());
      new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR, null, headers, null)
          .fillResponse(response);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR).fillResponse(response);
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
      throw new MyException(HttpStatusCode.SC_INTERNAL_SERVER_ERROR, "could not encode the generated CRL");
    }

    return new MgmtResponse.ByteArray(encoded);
  } // method toByteArray

  /**
   * The specified stream is closed after this method call.
   */
  private static String getNameFromRequest(InputStream in) throws CaMgmtException {
    MgmtRequest.Name req = parse(in, MgmtRequest.Name.class);
    return req.getName();
  } // method getNameFromRequest

  /**
   * The specified stream is closed after this method call.
   */
  private static <T extends MgmtRequest> T parse(InputStream in, Class<T> clazz)
      throws CaMgmtException {
    try (InputStream nin = in) {
      if (LOG.isDebugEnabled()) {
        byte[] reqBytes = IoUtil.readAllBytes(nin);
        LOG.debug("received request ({}): {}", clazz.getName(), new String(reqBytes));
        return CaJson.parseObject(reqBytes, clazz);
      } else {
        return CaJson.parseObject(nin, clazz);
      }
    } catch (IOException | RuntimeException ex) {
      String msg = "cannot parse request " + clazz + " from InputStream";
      LOG.error(msg, ex);
      throw new CaMgmtException(ex);
    }
  } // method parse

  private static <T extends MgmtRequest> T parse2(InputStream in, Class<T> clazz)
      throws CaMgmtException {
    try (InputStream nin = in) {
      return CaJson.parseObject(nin, clazz);
    } catch (IOException | RuntimeException ex) {
      String msg = "cannot parse request " + clazz + " from InputStream";
      LOG.error(msg, ex);
      throw new CaMgmtException(ex);
    }
  } // method parse

}
