// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.servlet;

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
import org.xipki.util.HttpConstants;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.InvalidConfException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
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

  }

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
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
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
        throw new MyException(HttpServletResponse.SC_NOT_FOUND, "unknown action '" + actionStr + "'");
      }

      InputStream in = request.getInputStream();
      MgmtResponse resp = null;

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
          break;
        }
        case addCaAlias: {
          MgmtRequest.AddCaAlias req = parse(in, MgmtRequest.AddCaAlias.class);
          caManager.addCaAlias(req.getAliasName(), req.getCaName());
          break;
        }
        case addCertprofile: {
          MgmtRequest.AddCertprofile req = parse(in, MgmtRequest.AddCertprofile.class);
          caManager.addCertprofile(req.getCertprofileEntry());
          break;
        }
        case addCertprofileToCa: {
          MgmtRequest.AddCertprofileToCa req = parse(in, MgmtRequest.AddCertprofileToCa.class);
          caManager.addCertprofileToCa(req.getProfileName(), req.getCaName());
          break;
        }
        case addPublisher: {
          MgmtRequest.AddPublisher req = parse(in, MgmtRequest.AddPublisher.class);
          caManager.addPublisher(req.getPublisherEntry());
          break;
        }
        case addPublisherToCa: {
          MgmtRequest.AddPublisherToCa req = parse(in, MgmtRequest.AddPublisherToCa.class);
          caManager.addPublisherToCa(req.getPublisherName(), req.getCaName());
          break;
        }
        case addRequestor: {
          MgmtRequest.AddRequestor req = parse(in, MgmtRequest.AddRequestor.class);
          caManager.addRequestor(req.getRequestorEntry());
          break;
        }
        case addRequestorToCa: {
          MgmtRequest.AddRequestorToCa req = parse(in, MgmtRequest.AddRequestorToCa.class);
          caManager.addRequestorToCa(req.getRequestor(), req.getCaName());
          break;
        }
        case addSigner: {
          MgmtRequest.AddSigner req = parse(in, MgmtRequest.AddSigner.class);
          caManager.addSigner(req.getSignerEntry().toSignerEntry());
          break;
        }
        case changeCa: {
          MgmtRequest.ChangeCa req = parse(in, MgmtRequest.ChangeCa.class);
          caManager.changeCa(req.getChangeCaEntry());
          break;
        }
        case changeCertprofile: {
          MgmtRequest.ChangeTypeConfEntity req = parse(in, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changeCertprofile(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changePublisher: {
          MgmtRequest.ChangeTypeConfEntity req = parse(in, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changePublisher(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changeRequestor: {
          MgmtRequest.ChangeTypeConfEntity req = parse(in, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changeRequestor(req.getName(), req.getType(), req.getConf());
          break;
        }
        case changeSigner: {
          MgmtRequest.ChangeSigner req = parse(in, MgmtRequest.ChangeSigner.class);
          caManager.changeSigner(req.getName(), req.getType(), req.getConf(), req.getBase64Cert());
          break;
        }
        case clearPublishQueue: {
          MgmtRequest.ClearPublishQueue req = new MgmtRequest.ClearPublishQueue();
          caManager.clearPublishQueue(req.getCaName(), req.getPublisherNames());
          break;
        }
        case exportConf: {
          MgmtRequest.ExportConf req = parse(in, MgmtRequest.ExportConf.class);
          InputStream confStream = caManager.exportConf(req.getCaNames());
          resp = new MgmtResponse.ByteArray(IoUtil.read(confStream));
          break;
        }
        case generateCertificate: {
          MgmtRequest.GenerateCert req = parse(in, MgmtRequest.GenerateCert.class);
          X509Cert cert = caManager.generateCertificate(req.getCaName(), req.getProfileName(),
              req.getEncodedCsr(), req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case generateCrossCertificate: {
          MgmtRequest.GenerateCrossCertificate req = parse(in, MgmtRequest.GenerateCrossCertificate.class);
          X509Cert cert = caManager.generateCrossCertificate(req.getCaName(), req.getProfileName(),
              req.getEncodedCsr(), req.getEncodedTargetCert(), req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case generateKeyCert: {
          MgmtRequest.GenerateKeyCert req = parse(in, MgmtRequest.GenerateKeyCert.class);
          KeyCertBytesPair keyCertBytesPair = caManager.generateKeyCert(req.getCaName(),
              req.getProfileName(), req.getSubject(), req.getNotBefore(), req.getNotAfter());
          resp = new MgmtResponse.KeyCertBytes(keyCertBytesPair.getKey(), keyCertBytesPair.getCert());
          break;
        }
        case generateCrlOnDemand: {
          resp = toByteArray(action, caManager.generateCrlOnDemand(getNameFromRequest(in)));
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

          X509Cert cert = caManager.generateRootCa(caEntry, req.getCertprofileName(), req.getSubject(),
              req.getSerialNumber(), req.getNotBefore(), req.getNotAfter());
          resp = toByteArray(cert);
          break;
        }
        case getAliasesForCa: {
          resp = new MgmtResponse.StringSet(caManager.getAliasesForCa(getNameFromRequest(in)));
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
          resp = new MgmtResponse.StringSet(caManager.getCaAliasNames());
          break;
        }
        case getCaNameForAlias: {
          String aliasName = getNameFromRequest(in);
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
          resp = new MgmtResponse.StringSet(caManager.getCertprofileNames());
          break;
        }
        case getCertprofilesForCa: {
          resp = new MgmtResponse.StringSet(caManager.getCertprofilesForCa(getNameFromRequest(in)));
          break;
        }
        case getCrl: {
          MgmtRequest.GetCrl req = parse(in, MgmtRequest.GetCrl.class);
          X509CRLHolder crl = caManager.getCrl(req.getCaName(), req.getCrlNumber());
          if (crl == null) {
            throw new CaMgmtException("Found no CRL for CA " + req.getCaName()
                        + " with CRL number 0x" + req.getCrlNumber().toString(16));
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
          resp = new MgmtResponse.StringSet(caManager.getFailedCaNames());
          break;
        }
        case getInactiveCaNames: {
          resp = new MgmtResponse.StringSet(caManager.getInactiveCaNames());
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
          resp = new MgmtResponse.StringSet(caManager.getPublisherNames());
          break;
        }
        case getPublishersForCa: {
          resp = new MgmtResponse.GetPublischersForCa(caManager.getPublishersForCa(getNameFromRequest(in)));
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
          resp = new MgmtResponse.StringSet(caManager.getRequestorNames());
          break;
        }
        case getRequestorsForCa: {
          resp = new MgmtResponse.GetRequestorsForCa(caManager.getRequestorsForCa(getNameFromRequest(in)));
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
          MgmtRequest.ListCertificates req = parse(in, MgmtRequest.ListCertificates.class);
          X500Name subjectPattern = X500Name.getInstance(req.getEncodedSubjectDnPattern());
          List<CertListInfo> result = caManager.listCertificates(req.getCaName(), subjectPattern,
              req.getValidFrom(), req.getValidTo(), req.getOrderBy(), req.getNumEntries());
          resp = new MgmtResponse.ListCertificates(result);
          break;
        }
        case loadConf: {
          MgmtRequest.LoadConf req = parse(in, MgmtRequest.LoadConf.class);
          Map<String, X509Cert> rootcaNameCertMap = caManager.loadConf(new ByteArrayInputStream(req.getConfBytes()));

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
          caManager.removeCa(getNameFromRequest(in));
          break;
        }
        case removeCaAlias: {
          caManager.removeCaAlias(getNameFromRequest(in));
          break;
        }
        case removeCertificate: {
          MgmtRequest.RemoveCertificate req = parse(in, MgmtRequest.RemoveCertificate.class);
          caManager.removeCertificate(req.getCaName(), req.getSerialNumber());
          break;
        }
        case removeCertprofile: {
          caManager.removeCertprofile(getNameFromRequest(in));
          break;
        }
        case removeCertprofileFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(in, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removeCertprofileFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removePublisher: {
          caManager.removePublisher(getNameFromRequest(in));
          break;
        }
        case removePublisherFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(in, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removePublisherFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removeRequestor: {
          caManager.removeRequestor(getNameFromRequest(in));
          break;
        }
        case removeRequestorFromCa: {
          MgmtRequest.RemoveEntityFromCa req = parse(in, MgmtRequest.RemoveEntityFromCa.class);
          caManager.removeRequestorFromCa(req.getEntityName(), req.getCaName());
          break;
        }
        case removeSigner: {
          caManager.removeSigner(getNameFromRequest(in));
          break;
        }
        case republishCertificates: {
          MgmtRequest.RepublishCertificates req = parse(in, MgmtRequest.RepublishCertificates.class);
          caManager.republishCertificates(req.getCaName(), req.getPublisherNames(), req.getNumThreads());
          break;
        }
        case restartCa: {
          caManager.restartCa(getNameFromRequest(in));
          break;
        }
        case restartCaSystem: {
          caManager.restartCaSystem();
          break;
        }
        case revokeCa: {
          MgmtRequest.RevokeCa req = parse(in, MgmtRequest.RevokeCa.class);
          caManager.revokeCa(req.getCaName(), req.getRevocationInfo());
          break;
        }
        case revokeCertficate:
        case revokeCertificate: {
          MgmtRequest.RevokeCertificate req = parse(in, MgmtRequest.RevokeCertificate.class);
          caManager.revokeCertificate(req.getCaName(), req.getSerialNumber(), req.getReason(), req.getInvalidityTime());
          break;
        }
        case tokenInfoP11: {
          MgmtRequest.TokenInfoP11 req = parse(in, MgmtRequest.TokenInfoP11.class);
          String info = caManager.getTokenInfoP11(req.getModuleName(), req.getSlotIndex(), req.isVerbose());
          resp = new MgmtResponse.StringResponse(info);
          break;
        }
        case unlockCa: {
          caManager.unlockCa();
          break;
        }
        case unrevokeCa: {
          caManager.unrevokeCa(getNameFromRequest(in));
          break;
        }
        case unsuspendCertificate: {
          MgmtRequest.UnsuspendCertificate req = parse(in, MgmtRequest.UnsuspendCertificate.class);
          caManager.unsuspendCertificate(req.getCaName(), req.getSerialNumber());
          break;
        }
        case addDbSchema: {
          MgmtRequest.AddOrChangeDbSchema req = parse(in, MgmtRequest.AddOrChangeDbSchema.class);
          caManager.addDbSchema(req.getName(), req.getValue());
          break;
        }
        case changeDbSchema: {
          MgmtRequest.AddOrChangeDbSchema req = parse(in, MgmtRequest.AddOrChangeDbSchema.class);
          caManager.changeDbSchema(req.getName(), req.getValue());
          break;
        }
        case removeDbSchema: {
          caManager.removeDbSchema(getNameFromRequest(in));
          break;
        }
        case getDbSchemas: {
          resp = new MgmtResponse.GetDbSchemas(caManager.getDbSchemas());
          break;
        }
        case addKeypairGen: {
          MgmtRequest.AddKeypairGen req = parse(in, MgmtRequest.AddKeypairGen.class);
          caManager.addKeypairGen(req.getEntry());
          break;
        }
        case changeKeypairGen: {
          MgmtRequest.ChangeTypeConfEntity req = parse(in, MgmtRequest.ChangeTypeConfEntity.class);
          caManager.changeKeypairGen(req.getName(), req.getType(), req.getConf());
          break;
        }
        case removeKeypairGen: {
          caManager.removeKeypairGen(getNameFromRequest(in));
          break;
        }
        case getKeypairGenNames: {
          resp = new MgmtResponse.StringSet(caManager.getKeypairGenNames());
          break;
        }
        case getKeypairGen: {
          String name = getNameFromRequest(in);
          KeypairGenEntry result = caManager.getKeypairGen(name);
          if (result == null) {
            throw new CaMgmtException("Unknown KeypairGen " + name);
          }
          resp = new MgmtResponse.GetKeypairGen(result);
          break;
        }
        default: {
          throw new MyException(HttpServletResponse.SC_NOT_FOUND, "unsupported action " + actionStr);
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
      throw new MyException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "could not encode the generated CRL");
    }

    return new MgmtResponse.ByteArray(encoded);
  } // method toByteArray

  private static String getNameFromRequest(InputStream in) throws CaMgmtException {
    MgmtRequest.Name req = parse(in, MgmtRequest.Name.class);
    return req.getName();
  } // method getNameFromRequest

  private static <T extends MgmtRequest> T parse(InputStream in, Class<T> clazz)
      throws CaMgmtException {
    try {
      return JSON.parseObject(in, clazz);
    } catch (RuntimeException ex) {
      throw new CaMgmtException("cannot parse request " + clazz + " from InputStream");
    }
  } // method parse

}
