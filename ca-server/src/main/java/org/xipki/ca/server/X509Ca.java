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

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.ca.server.db.CertStore;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.license.api.CmLicense;
import org.xipki.security.*;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.ctlog.CtLog.SignedCertificateTimestampList;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.exception.BadCertTemplateException;
import org.xipki.util.exception.OperationException;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import static org.xipki.ca.sdk.CaAuditConstants.TYPE_downlaod_crl4number;
import static org.xipki.ca.sdk.CaAuditConstants.TYPE_download_crl;
import static org.xipki.util.Args.notEmpty;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.exception.ErrorCode.*;

/**
 * X509CA.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509Ca extends X509CaModule implements Closeable {

  static class GrantedCertTemplate {

    private final BigInteger certId;

    private final ConcurrentContentSigner signer;
    private final Extensions extensions;
    private final IdentifiedCertprofile certprofile;
    private final Date grantedNotBefore;
    private final Date grantedNotAfter;
    private final X500Name requestedSubject;
    private final SubjectPublicKeyInfo grantedPublicKey;
    private final PrivateKeyInfo privateKey;
    private final String warning;

    private X500Name grantedSubject;
    private String grantedSubjectText;

    GrantedCertTemplate(BigInteger certId, Extensions extensions, IdentifiedCertprofile certprofile,
        Date grantedNotBefore, Date grantedNotAfter, X500Name requestedSubject, SubjectPublicKeyInfo grantedPublicKey,
        PrivateKeyInfo privateKey, ConcurrentContentSigner signer, String warning) {
      this.certId = certId == null ? BigInteger.ZERO : certId;
      this.extensions = extensions;
      this.certprofile = certprofile;
      this.grantedNotBefore = grantedNotBefore;
      this.grantedNotAfter = grantedNotAfter;
      this.requestedSubject = requestedSubject;
      this.grantedPublicKey = grantedPublicKey;
      this.privateKey = privateKey;
      this.signer = signer;
      this.warning = warning;
    }

    void setGrantedSubject(X500Name subject) {
      this.grantedSubject = subject;
      this.grantedSubjectText = X509Util.x500NameText(subject);
    }

    void audit(AuditEvent event) {
      String prefix = certId + ".";
      if (!grantedSubject.equals(requestedSubject)) {
        event.addEventData(prefix + CaAuditConstants.NAME_req_subject,
            "\"" + X509Util.x500NameText(requestedSubject) + "\"");
      }

      event.addEventData(prefix + CaAuditConstants.NAME_subject,
          "\"" + X509Util.x500NameText(grantedSubject) + "\"");
      event.addEventData(prefix + CaAuditConstants.NAME_certprofile,
          certprofile.getIdent().getName());
      event.addEventData(prefix + CaAuditConstants.NAME_not_before,
          DateUtil.toUtcTimeyyyyMMddhhmmss(grantedNotBefore));
      event.addEventData(prefix + CaAuditConstants.NAME_not_after,
          DateUtil.toUtcTimeyyyyMMddhhmmss(grantedNotAfter));
    }
  }

  static class OperationExceptionWithIndex extends OperationException {

    private static final long serialVersionUID = 1L;

    private final int index;

    public OperationExceptionWithIndex(int index, OperationException underlying) {
      super(underlying.getErrorCode(), underlying.getErrorMessage());
      this.index = index;
    }

    public int getIndex() {
      return index;
    }

  }

  private static final Logger LOG = LoggerFactory.getLogger(X509Ca.class);

  private final CtLogClient ctlogClient;

  private final CertStore certstore;

  private final CaIdNameMap caIdNameMap;

  private final CaManagerImpl caManager;

  private final X509PublisherModule publisherModule;

  private final X509CrlModule crlModule;

  private final GrandCertTemplateBuilder grandCertTemplateBuilder;

  private final X509RevokerModule revokerModule;

  private final X509RemoverModule removerModule;

  private final boolean saveCert;

  private final boolean saveKeypair;

  public X509Ca(CaManagerImpl caManager, CaInfo caInfo, CertStore certstore,
      CtLogClient ctlogClient) throws OperationException {
    super(caInfo);

    if (caInfo.isSignerRequired()) {
      try {
        caInfo.initSigner(caManager.getSecurityFactory());
      } catch (XiSecurityException ex) {
        LogUtil.error(LOG, ex, "security.createSigner caSigner for CA " + caIdent);
        throw new OperationException(SYSTEM_FAILURE, ex);
      }
    }

    this.caManager = notNull(caManager, "caManager");
    this.caIdNameMap = caManager.idNameMap();
    this.ctlogClient = ctlogClient;
    this.certstore = notNull(certstore, "certstore");

    this.publisherModule = new X509PublisherModule(caManager, caInfo, certstore);
    this.crlModule = new X509CrlModule(caManager, caInfo, certstore, publisherModule);
    this.grandCertTemplateBuilder = new GrandCertTemplateBuilder(caInfo, certstore);
    this.revokerModule = new X509RevokerModule(caManager, caInfo, certstore, publisherModule);
    this.removerModule = new X509RemoverModule(caManager, caInfo, certstore, publisherModule);
    this.saveKeypair = caInfo.isSaveKeypair();
    this.saveCert = caInfo.isSaveCert();
    if (!this.saveCert) {
      LOG.warn("CA {}: Certificates will not be saved in the database and will not be published!",
          caInfo.getIdent().getName());
    }

    if (!this.saveCert) {
      if (caInfo.isSaveRequest()) {
        // Request cannot be saved if SAVE_CERT (in EXTRA_CONTROL) is set to false.
        caInfo.setSaveRequest(false);
        LOG.warn("CA {}: SAVE_REQ is configured to true, ignore it, use 'false' instead", caInfo.getIdent().getName());
      }
    }
  } // constructor

  public NameId getCaIdent() {
    return caIdent;
  }

  public CaInfo getCaInfo() {
    return caInfo;
  }

  public X509Cert getCaCert() {
    return caCert;
  }

  public List<byte[]> getEncodedCaCertChain() {
    return encodedCaCertChain;
  }

  public X509Cert getCert(BigInteger serialNumber)
      throws CertificateException, OperationException {
    CertificateInfo certInfo = certstore.getCertInfo(caIdent, caCert, serialNumber, caIdNameMap);
    return (certInfo == null) ? null : certInfo.getCert().getCert();
  }

  /**
   * Returns the certificate satisfying the given search criteria.
   * @param subjectName Subject of the certificate.
   * @param transactionId transactionId.
   * @return the certificate satisfying the given search criteria
   * @throws OperationException
   *         if error occurs.
   */
  public X509Cert getCert(X500Name subjectName, String transactionId)
      throws OperationException {
    return certstore.getCert(subjectName, transactionId);
  }

  public CertWithRevocationInfo getCertWithRevocationInfo(BigInteger serialNumber)
      throws CertificateException, OperationException {
    return certstore.getCertWithRevocationInfo(caIdent.getId(), serialNumber, caIdNameMap);
  }

  public byte[] getCertRequest(BigInteger serialNumber) throws OperationException {
    return certstore.getCertRequest(caIdent, serialNumber);
  }

  public List<CertListInfo> listCerts(
      X500Name subjectPattern, Date validFrom, Date validTo, CertListOrderBy orderBy, int numEntries)
      throws OperationException {
    return certstore.listCerts(caIdent, subjectPattern, validFrom, validTo, orderBy, numEntries);
  }

  public X509CRLHolder getCurrentCrl() throws OperationException {
    return getCrl(null);
  }

  public X509CRLHolder getCrl(BigInteger crlNumber) throws OperationException {
    AuditEvent event = newPerfAuditEvent(crlNumber == null ? TYPE_download_crl : TYPE_downlaod_crl4number);
    boolean succ = false;
    try {
      X509CRLHolder ret = crlModule.getCrl(crlNumber, event);
      succ = true;
      return ret;
    } finally {
      finish(event, succ);
    }
  } // method getCrl

  public X509CRLHolder getCrl(BigInteger crlNumber, AuditEvent event) throws OperationException {
    return crlModule.getCrl(crlNumber, event);
  } // method getCrl

  public X509CRLHolder generateCrlOnDemand() throws OperationException {
    return crlModule.generateCrlOnDemand();
  }

  public CertificateInfo regenerateCert(CertTemplateData certTemplate, RequestorInfo requestor,
      String transactionId, AuditEvent event) throws OperationException {
    return regenerateCerts(Collections.singletonList(certTemplate), requestor, transactionId, event).get(0);
  }

  public List<CertificateInfo> regenerateCerts(List<CertTemplateData> certTemplates,
      RequestorInfo requestor, String transactionId, AuditEvent event)
      throws OperationException {
    return generateCerts(certTemplates, requestor, true, transactionId, event);
  }

  public boolean republishCerts(List<String> publisherNames, int numThreads) {
    return publisherModule.republishCerts(publisherNames, numThreads);
  }

  public void clearPublishQueue(List<String> publisherNames) throws CaMgmtException {
    publisherModule.clearPublishQueue(publisherNames);
  }

  public boolean publishCertsInQueue() {
    return publisherModule.publishCertsInQueue();
  }

  public CertWithRevocationInfo revokeCert(BigInteger serialNumber, CrlReason reason, Date invalidityTime)
      throws OperationException {
    AuditEvent event = newAuditEvent(CaAuditConstants.TYPE_revoke_cert);
    boolean succ = false;
    try {
      CertWithRevocationInfo ret = revokerModule.revokeCert(serialNumber, reason, invalidityTime, event);
      succ = true;
      return ret;
    } finally {
      finish(event, succ);
    }
  }

  public CertWithRevocationInfo revokeCert(BigInteger serialNumber, CrlReason reason,
      Date invalidityTime, AuditEvent event) throws OperationException {
    return revokerModule.revokeCert(serialNumber, reason, invalidityTime, event);
  }

  public CertWithDbId unsuspendCert(BigInteger serialNumber)
      throws OperationException {
    AuditEvent event = newAuditEvent(CaAuditConstants.TYPE_unsuspend_cert);
    boolean succ = false;
    try {
      CertWithDbId ret = unsuspendCert(serialNumber, event);
      succ = true;
      return ret;
    } finally {
      finish(event, succ);
    }
  }

  public CertWithDbId unsuspendCert(BigInteger serialNumber, AuditEvent event)
      throws OperationException {
    return revokerModule.unsuspendCert(serialNumber, event);
  }

  public CertWithDbId removeCert(BigInteger serialNumber)
      throws OperationException {
    AuditEvent event = newAuditEvent(CaAuditConstants.TYPE_remove_cert);
    boolean succ = false;
    try {
      CertWithDbId ret = removeCert(serialNumber, event);
      succ = true;
      return ret;
    } finally {
      finish(event, succ);
    }
  }

  public CertWithDbId removeCert(BigInteger serialNumber, AuditEvent event)
      throws OperationException {
    return removerModule.removeCert(serialNumber, event);
  }

  public void revokeCa(CertRevocationInfo revocationInfo) throws OperationException {
    revokerModule.revokeCa(revocationInfo);
  }

  public void unrevokeCa() throws OperationException {
    revokerModule.unrevokeCa();
  }

  public long addRequest(byte[] request) throws OperationException {
    return certstore.addRequest(request);
  }

  public void addRequestCert(long requestId, long certId) throws OperationException {
    certstore.addRequestCert(requestId, certId);
  }

  public List<CertificateInfo> generateCerts(
      List<CertTemplateData> certTemplates, RequestorInfo requestor, String transactionId, AuditEvent event)
      throws OperationException {
    return generateCerts(certTemplates, requestor, false, transactionId, event);
  }

  private List<CertificateInfo> generateCerts(
      List<CertTemplateData> certTemplates, RequestorInfo requestor, boolean update,
      String transactionId, AuditEvent event)
      throws OperationExceptionWithIndex {
    notEmpty(certTemplates, "certTemplates");

    CmLicense license = caManager.getLicense();
    if (!license.isValid()) {
      LOG.error("License not valid yet or expired, need new license");
      throw new OperationExceptionWithIndex(0, // we have to specify an index, use 0.
          new OperationException( SYSTEM_FAILURE, "License not valid yet or expired"));
    }

    final int n = certTemplates.size();
    List<GrantedCertTemplate> gcts = new ArrayList<>(n);

    List<KeypairGenerator> keypairGenerators = null;
    boolean caGenKeypair = false;
    for (CertTemplateData certTemplate : certTemplates) {
      if (certTemplate.isCaGenerateKeypair()) {
        caGenKeypair = true;
        break;
      }
    }

    if (caGenKeypair) {
      List<String> keypairGenNames = caInfo.getKeypairGenNames();
      if (CollectionUtil.isNotEmpty(keypairGenNames)) {
        keypairGenerators = new ArrayList<>(keypairGenNames.size());
        for (String name : keypairGenNames) {
          KeypairGenerator keypairGen = caManager.getKeypairGenerator(name);
          if (keypairGen != null) {
            keypairGenerators.add(keypairGen);
          }
        }
      }
    }

    for (int i = 0; i < n; i++) {
      CertTemplateData certTemplate = certTemplates.get(i);
      try {
        IdentifiedCertprofile certprofile = getX509Certprofile(certTemplate.getCertprofileName());

        if (certprofile == null) {
          throw new OperationException(UNKNOWN_CERT_PROFILE,
              "unknown cert profile " + certTemplate.getCertprofileName());
        }

        GrantedCertTemplate gct = grandCertTemplateBuilder.create(certprofile, certTemplate, keypairGenerators, update);
        gct.audit(event);
        gcts.add(gct);
      } catch (OperationException ex) {
        LOG.error("     FAILED createGrantedCertTemplate: CA={}, profile={}, subject='{}'",
            caIdent.getName(), certTemplate.getCertprofileName(), certTemplate.getSubject());
        event.addEventData(certTemplate.getCertReqId() + "." + CaAuditConstants.NAME_message, ex.getMessage());
        throw new OperationExceptionWithIndex(i, ex);
      }
    }

    List<CertificateInfo> certInfos = new ArrayList<>(n);
    OperationExceptionWithIndex exception = null;

    for (int i = 0; i < n; i++) {
      if (exception != null) {
        break;
      }
      GrantedCertTemplate gct = gcts.get(i);
      final NameId certprofilIdent = gct.certprofile.getIdent();
      final String subjectText = gct.grantedSubjectText;
      LOG.info("     START generateCertificate: CA={}, profile={}, subject='{}'",
          caIdent.getName(), certprofilIdent.getName(), subjectText);

      boolean successful = false;
      try {
        //-----begin license-----
        // check CA
        String caSubject = caInfo.getCert().getSubjectText();
        if (!(license.grantAllCAs() || license.grant(caSubject))) {
          LOG.error("Not granted for CA {}, need new license", caSubject);
          throw new OperationException(SYSTEM_FAILURE, "new license needed");
        }

        // check number of certificate
        long maxNumOfCerts = license.getMaxNumberOfCerts();
        if (maxNumOfCerts >= 0) {
          long numOfCerts = certstore.getCountOfCerts(0);
          if (numOfCerts >= maxNumOfCerts) {
            LOG.error("Maximal {} certificates is allowed, {} already issued, need new license",
                maxNumOfCerts, numOfCerts);
            throw new OperationException(SYSTEM_FAILURE, "new license needed");
          }
        }

        // regulate speed
        license.regulateSpeed();
        //-----end license-----

        CertificateInfo certInfo = generateCert(i, gct, requestor, transactionId, event);
        successful = true;
        certInfos.add(certInfo);

        if (LOG.isInfoEnabled()) {
          String prefix = certInfo.isAlreadyIssued() ? "RETURN_OLD_CERT" : "SUCCESSFUL";
          CertWithDbId cert = certInfo.getCert();
          LOG.info("{} generateCertificate: CA={}, profile={}, subject='{}', serialNumber={}",
              prefix, caIdent.getName(), certprofilIdent.getName(),
              cert.getCert().getSubjectText(), cert.getCert().getSerialNumberHex());
        }
      } catch (OperationException ex) {
        exception = new OperationExceptionWithIndex(i, ex);
      } catch (Throwable th) {
        exception = new OperationExceptionWithIndex(i, new OperationException(SYSTEM_FAILURE, th));
      } finally {
        if (!successful) {
          LOG.error("    FAILED generateCertificate: CA={}, profile={}, subject='{}'",
              caIdent.getName(), certprofilIdent.getName(), subjectText);
        }
      }
    }

    if (exception != null) {
      LOG.error("could not generate certificate for request[{}], reverted all generated certificates",
          exception.getIndex());
      // delete generated certificates
      for (CertificateInfo m : certInfos) {
        BigInteger serial = m.getCert().getCert().getSerialNumber();
        try {
          removeCert(serial, event);
        } catch (Throwable thr) {
          LogUtil.error(LOG, thr, "could not delete certificate serial=" + serial);
        }
      }

      LogUtil.warn(LOG, exception);
      throw exception;
    }

    return certInfos;
  }

  public CertificateInfo generateCert(
      CertTemplateData certTemplate, RequestorInfo requestor, String transactionId, AuditEvent event)
      throws OperationException {
    notNull(certTemplate, "certTemplate");
    return generateCerts(Collections.singletonList(certTemplate), requestor, transactionId, event).get(0);
  }

  private CertificateInfo generateCert(
      int index, GrantedCertTemplate gct, RequestorInfo requestor, String transactionId, AuditEvent event)
      throws OperationExceptionWithIndex {
    boolean successful = false;
    try {
      CertificateInfo ret = generateCert0(gct, requestor, transactionId, event);
      successful = (ret != null);
      return ret;
    } catch (OperationException ex) {
      event.addEventData(gct.certId + "." + CaAuditConstants.NAME_message, ex.getMessage());
      if (ex instanceof OperationExceptionWithIndex) {
        throw (OperationExceptionWithIndex) ex;
      } else {
        throw new OperationExceptionWithIndex(index, ex);
      }
    } finally {
      setEventStatus(event, successful);
    }
  }

  private CertificateInfo generateCert0(
      GrantedCertTemplate gct, RequestorInfo requestor, String transactionId, AuditEvent event)
      throws OperationException {
    notNull(gct, "gct");

    IdentifiedCertprofile certprofile = gct.certprofile;

    ExtensionControl extnSctCtrl = certprofile.getExtensionControls().get(Extn.id_SCTs);
    boolean ctlogEnabled = caInfo.getCtlogControl() != null && caInfo.getCtlogControl().isEnabled();

    if (!ctlogEnabled) {
      if (extnSctCtrl != null && extnSctCtrl.isRequired()) {
        throw new OperationException(SYSTEM_FAILURE,
            "extension " + ObjectIdentifiers.getName(Extn.id_SCTs)
            + " is required but CTLog of the CA is not activated");
      }
    }

    String auditPrefix = gct.certId + ".";

    String serialNumberMode = certprofile.getSerialNumberMode();

    BigInteger serialNumber = null;
    while (true) {
      if (StringUtil.isBlank(serialNumberMode) || "CA".equalsIgnoreCase(serialNumberMode)) {
        serialNumber = caInfo.nextSerial();
      } else if ("PROFILE".equalsIgnoreCase(serialNumberMode)) {
        try {
          BigInteger previousSerialNumber = serialNumber;

          ConfPairs extraControl = caInfo.getExtraControl();
          serialNumber = certprofile.generateSerialNumber(
                  caInfo.getCert().getSubject(),
                  caInfo.getCert().getSubjectPublicKeyInfo(),
                  gct.requestedSubject,
                  gct.grantedPublicKey,
                  extraControl == null ? null : extraControl.unmodifiable());

          // if the CertProfile generates always the serial number for fixed input,
          // do not repeat this process.
          if (serialNumber.equals(previousSerialNumber)) {
            String message = "serialNumber generated by the profile " + certprofile.getIdent().getName()
                + " has been used before.";
            throw new OperationException(BAD_CERT_TEMPLATE, message);
          }
        } catch (CertprofileException ex) {
          String message = "error generateSerialNumber";
          LogUtil.error(LOG, ex, message);
          throw new OperationException(SYSTEM_FAILURE, message);
        }
      } else {
        throw new OperationException(BAD_CERT_TEMPLATE, "unknown SerialNumberMode '" + serialNumberMode + "'");
      }

      if (certstore.getCertId(caIdent, serialNumber) == 0) {
          break;
      }
    }

    event.addEventData(auditPrefix + CaAuditConstants.NAME_serial, LogUtil.formatCsn(serialNumber));

    X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
        caInfo.getPublicCaInfo().getSubject(), serialNumber, gct.grantedNotBefore,
        gct.grantedNotAfter, gct.grantedSubject, gct.grantedPublicKey);

    CertificateInfo ret;

    try {
      SignerEntryWrapper crlSigner = crlModule.getCrlSigner();
      X509Cert crlSignerCert = (crlSigner == null) ? null : crlSigner.getSigner().getCertificate();

      ExtensionValues extensionTuples = certprofile.getExtensions(gct.requestedSubject,
          gct.grantedSubject, gct.extensions, gct.grantedPublicKey, caInfo.getPublicCaInfo(),
          crlSignerCert, gct.grantedNotBefore, gct.grantedNotAfter);
      if (extensionTuples != null) {
        for (ASN1ObjectIdentifier extensionType : extensionTuples.getExtensionTypes()) {
          ExtensionValue extValue = extensionTuples.getExtensionValue(extensionType);
          certBuilder.addExtension(extensionType, extValue.isCritical(), extValue.getValue());
        }
      }

      boolean addCtlog = ctlogEnabled && extnSctCtrl != null;

      if (addCtlog) {
        certBuilder.addExtension(Extn.id_precertificate, true, DERNull.INSTANCE);

        ConcurrentBagEntrySigner signer0;
        try {
          signer0 = gct.signer.borrowSigner();
        } catch (NoIdleSignerException ex) {
          throw new OperationException(SYSTEM_FAILURE, ex);
        }

        X509CertificateHolder precert;
        try {
          precert = certBuilder.build(signer0.value());
        } finally {
          // returns the signer after the signing so that it can be used by others
          gct.signer.requiteSigner(signer0);
        }

        CtLogPublicKeyFinder finder = caManager.getCtLogPublicKeyFinder();
        if (finder == null) {
          throw new OperationException(SYSTEM_FAILURE, "ctLog not configured for CA " + caInfo.getIdent().getName());
        }

        SignedCertificateTimestampList scts = ctlogClient.getCtLogScts(precert, caCert, caInfo.getCertchain(), finder);

        // remove the precertificate extension
        certBuilder.removeExtension(Extn.id_precertificate);

        // add the SCTs extension
        DEROctetString extnValue;
        try {
          extnValue = new DEROctetString(new DEROctetString(scts.getEncoded()).getEncoded());
        } catch (IOException ex) {
          throw new CertIOException("could not encode SCT extension", ex);
        }
        certBuilder.addExtension(new Extension(Extn.id_SCTs, extnSctCtrl.isCritical(), extnValue));
      }

      ConcurrentBagEntrySigner signer0;
      try {
        signer0 = gct.signer.borrowSigner();
      } catch (NoIdleSignerException ex) {
        throw new OperationException(SYSTEM_FAILURE, ex);
      }

      X509CertificateHolder bcCert;
      try {
        bcCert = certBuilder.build(signer0.value());
      } finally {
        gct.signer.requiteSigner(signer0);
      }

      byte[] encodedCert = bcCert.getEncoded();
      int maxCertSize = gct.certprofile.getMaxCertSize();
      if (maxCertSize > 0) {
        int certSize = encodedCert.length;
        if (certSize > maxCertSize) {
          throw new OperationException(NOT_PERMITTED,
            String.format("certificate exceeds the maximal allowed size: %d > %d", certSize, maxCertSize));
        }
      }

      X509Cert cert = new X509Cert(bcCert, encodedCert);
      if (!verifySignature(cert)) {
        throw new OperationException(SYSTEM_FAILURE, "could not verify the signature of generated certificate");
      }

      CertWithDbId certWithMeta = new CertWithDbId(cert);
      ret = new CertificateInfo(certWithMeta, gct.privateKey, caIdent, caCert,
              gct.certprofile.getIdent(), requestor.getIdent());
      ret.setTransactionId(transactionId);
      ret.setRequestedSubject(gct.requestedSubject);

      if (saveCert && publisherModule.publishCert(ret, saveKeypair) == 1) {
        throw new OperationException(SYSTEM_FAILURE, "could not save certificate");
      }
    } catch (BadCertTemplateException ex) {
      throw new OperationException(BAD_CERT_TEMPLATE, ex);
    } catch (OperationException ex) {
      throw ex;
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "could not generate certificate");
      throw new OperationException(SYSTEM_FAILURE, th);
    }

    if (gct.warning != null) {
      ret.setWarningMessage(gct.warning);
    }

    return ret;
  } // method generateCertificate0

  public IdentifiedCertprofile getX509Certprofile(String certprofileName) {
    if (certprofileName == null) {
      return null;
    }

    Set<String> profileNames = caManager.getCertprofilesForCa(caIdent.getName());
    return (profileNames == null || !profileNames.contains(certprofileName))
        ? null : caManager.getIdentifiedCertprofile(certprofileName);
  } // method getX509Certprofile

  public RequestorInfo.CertRequestorInfo getRequestor(X509Cert requestorCert) {
    Set<CaHasRequestorEntry> requestorEntries = caManager.getRequestorsForCa(caIdent.getName());
    if (CollectionUtil.isEmpty(requestorEntries)) {
      return null;
    }

    for (CaHasRequestorEntry m : requestorEntries) {
      RequestorEntryWrapper entry = caManager.getRequestorWrapper(m.getRequestorIdent().getName());
      if (!RequestorEntry.TYPE_CERT.equals(entry.getDbEntry().getType())) {
        continue;
      }

      if (entry.getCert().getCert().equals(requestorCert)) {
        return new RequestorInfo.CertRequestorInfo(m, entry.getCert());
      }
    }

    return null;
  }

  public boolean healthy() {
    ConcurrentContentSigner signer = caInfo.getSigner(null);

    boolean healthy = true;
    if (signer != null) {
      healthy = signer.isHealthy();
    }

    if (healthy) {
      healthy = certstore.isHealthy();
    }

    if (healthy) {
      healthy = crlModule.healthy();
    }

    return healthy;
  } // method healthCheck

  public String getHexSha1OfCert() {
    return caInfo.getHexSha1OfCert();
  }

  @Override
  public void close() {
    crlModule.close();
    revokerModule.close();

    ScheduledThreadPoolExecutor executor = caManager.getScheduledThreadPoolExecutor();
    if (executor != null) {
      executor.purge();
    }
  }

}
