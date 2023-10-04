// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.servlet;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.MgmtMessage.CaEntryWrapper;
import org.xipki.ca.api.mgmt.MgmtMessage.MgmtAction;
import org.xipki.ca.api.mgmt.MgmtMessage.SignerEntryWrapper;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.security.KeyCertBytesPair;
import org.xipki.security.X509Cert;
import org.xipki.security.util.JSON;
import org.xipki.security.util.TlsHelper;
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.Map.Entry;

import static org.xipki.util.Args.notEmpty;
import static org.xipki.util.Args.notNull;

/**
 * CA management servlet.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class HttpMgmtServlet0 {

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

  private static final Logger LOG = LoggerFactory.getLogger(HttpMgmtServlet0.class);

  private static final String CT_RESPONSE = "application/json";

  private Set<X509Cert> mgmtCerts;

  private CaManager caManager;

  public void setMgmtCerts(Set<X509Cert> mgmtCerts) {
    this.mgmtCerts = new HashSet<>(notEmpty(mgmtCerts, "mgmtCerts"));
  }

  public void setCaManager(CaManager caManager) {
    this.caManager = notNull(caManager, "caManager");
  }

  public XiHttpResponse doPost(XiHttpRequest request) {
    try {
      X509Cert clientCert = TlsHelper.getTlsClientCert(request);
      if (clientCert == null) {
        throw new MyException(HttpStatusCode.SC_UNAUTHORIZED,
            "remote management is not permitted if TLS client certificate is not present");
      }

      if (!mgmtCerts.contains(clientCert)) {
        throw new MyException(HttpStatusCode.SC_UNAUTHORIZED,
            "remote management is not permitted to the client without valid certificate");
      }

      String path = (String) request.getAttribute(HttpConstants.ATTR_XIPKI_PATH);

      if (path == null || path.length() < 2) {
        throw new MyException(HttpStatusCode.SC_NOT_FOUND, "no action is specified");
      }

      String actionStr = path.substring(1);
      MgmtAction action = MgmtAction.ofName(actionStr);
      if (action == null) {
        throw new MyException(HttpStatusCode.SC_NOT_FOUND, "unknown action '" + actionStr + "'");
      }

      MgmtResponse resp = null;

      InputStream requestStream = request.getInputStream();

      switch (action) {
        case addCa: {
          MgmtRequest.AddCa req = parse(requestStream, MgmtRequest.AddCa.class);
          CaEntry caEntry;
          try {
            caEntry = req.getCaEntry().toCaEntry();
          } catch (CertificateException | InvalidConfException ex) {
            LOG.error(action + ": could not build the CaEntry", ex);
            throw new MyException(HttpStatusCode.SC_BAD_REQUEST,
                "could not build the CaEntry: " + ex.getMessage());
          }
          caManager.addCa(caEntry);
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
          caManager.addSigner(req.getSignerEntry().toSignerEntry());
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

          CaEntry caEntry;
          try {
            caEntry = req.getCaEntry().toCaEntry();
          } catch (CertificateException | InvalidConfException ex) {
            LOG.error(action + ": could not build the CaEntry", ex);
            throw new MyException(HttpStatusCode.SC_BAD_REQUEST,
                "could not build the CaEntry: " + ex.getMessage());
          }

          X509Cert cert = caManager.generateRootCa(caEntry, req.getCertprofileName(), req.getSubject(),
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
          CaEntry caEntry = caManager.getCa(name);
          if (caEntry == null) {
            throw new CaMgmtException("Unknown CA " + name);
          }
          resp = new MgmtResponse.GetCa(new CaEntryWrapper(caEntry));
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

          resp = new MgmtResponse.GetCert(new MgmtResponse.CertWithRevocationInfoWrapper(cert));
          break;
        }
        case getCertprofile: {
          String name = getNameFromRequest(requestStream);
          CertprofileEntry result = caManager.getCertprofile(name);
          if (result == null) {
            throw new CaMgmtException("Unknown Certprofile " + name);
          }
          resp = new MgmtResponse.GetCertprofile(result);
          break;
        }
        case getCertprofileNames: {
          resp = new MgmtResponse.StringSet(caManager.getCertprofileNames());
          break;
        }
        case getCertprofilesForCa: {
          resp = new MgmtResponse.StringSet(caManager.getCertprofilesForCa(getNameFromRequest(requestStream)));
          break;
        }
        case getCrl: {
          MgmtRequest.GetCrl req = parse(requestStream, MgmtRequest.GetCrl.class);
          X509CRLHolder crl = caManager.getCrl(req.getCaName(), req.getCrlNumber());
          if (crl == null) {
            throw new CaMgmtException("Found no CRL for CA " + req.getCaName()
                        + " with CRL number 0x" + req.getCrlNumber().toString(16));
          }
          resp = toByteArray(action, crl);
          break;
        }
        case getCurrentCrl: {
          String caName = getNameFromRequest(requestStream);
          X509CRLHolder crl = caManager.getCurrentCrl(caName);
          if (crl == null) {
            throw new CaMgmtException("No current CRL for CA " + caName);
          }
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
          PublisherEntry result = caManager.getPublisher(name);
          if (result == null) {
            throw new CaMgmtException("Unknown publisher " + name);
          }
          resp = new MgmtResponse.GetPublisher(result);
          break;
        }
        case getPublisherNames: {
          resp = new MgmtResponse.StringSet(caManager.getPublisherNames());
          break;
        }
        case getPublishersForCa: {
          resp = new MgmtResponse.GetPublischersForCa(caManager.getPublishersForCa(getNameFromRequest(requestStream)));
          break;
        }
        case getRequestor: {
          String name = getNameFromRequest(requestStream);
          RequestorEntry result = caManager.getRequestor(name);
          if (result == null) {
            throw new CaMgmtException("Unknown requestor " + name);
          }
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
          SignerEntry result = caManager.getSigner(name);
          if (result == null) {
            throw new CaMgmtException("Unknown signer " + name);
          }
          resp = new MgmtResponse.GetSigner(new SignerEntryWrapper(result));
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

          Map<String, X509Cert> rootcaNameCertMap = caManager.loadConf(req.getConfBytes());

          if (rootcaNameCertMap == null || rootcaNameCertMap.isEmpty()) {
            resp = new MgmtResponse.LoadConf(null);
          } else {
            Map<String, byte[]> result = new HashMap<>(rootcaNameCertMap.size());
            for (Entry<String, X509Cert> entry : rootcaNameCertMap.entrySet()) {
              byte[] encodedCert = entry.getValue().getEncoded();
              result.put(entry.getKey(), encodedCert);
            }
            resp = new MgmtResponse.LoadConf(result);
          }

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
        case tokenInfoP11: {
          MgmtRequest.TokenInfoP11 req = parse(requestStream, MgmtRequest.TokenInfoP11.class);
          String info = caManager.getTokenInfoP11(req.getModuleName(), req.getSlotIndex(), req.isVerbose());
          resp = new MgmtResponse.StringResponse(info);
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
          KeypairGenEntry result = caManager.getKeypairGen(name);
          if (result == null) {
            throw new CaMgmtException("Unknown KeypairGen " + name);
          }
          resp = new MgmtResponse.GetKeypairGen(result);
          break;
        }
        default: {
          throw new MyException(HttpStatusCode.SC_NOT_FOUND, "unsupported action " + actionStr);
        }
      }

      byte[] respBytes = resp == null ? new byte[0] : JSON.toJSONBytes(resp);
      return new XiHttpResponse(HttpStatusCode.SC_OK, CT_RESPONSE, null, respBytes);
    } catch (MyException ex) {
      Map<String, String> headers = Collections.singletonMap(HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());
      return new XiHttpResponse(ex.getStatus(), null, headers, null);
    } catch (CaMgmtException ex) {
      LOG.error("CaMgmtException", ex);
      Map<String, String> headers = Collections.singletonMap(HttpConstants.HEADER_XIPKI_ERROR, ex.getMessage());
      return new XiHttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR, null, headers, null);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      return new XiHttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
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
        return JSON.parseObject(reqBytes, clazz);
      } else {
        return JSON.parseObject(nin, clazz);
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
      return JSON.parseObject(nin, clazz);
    } catch (IOException | RuntimeException ex) {
      String msg = "cannot parse request " + clazz + " from InputStream";
      LOG.error(msg, ex);
      throw new CaMgmtException(ex);
    }
  } // method parse

}
