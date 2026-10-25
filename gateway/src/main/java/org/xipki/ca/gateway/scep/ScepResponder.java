// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.pkix.asn1.cms.ContentInfo;
import org.xipki.pkix.asn1.cms.IssuerAndSerialNumber;
import org.xipki.pkix.asn1.cms.SignedData;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.pkix.asn1.scep.IssuerAndSubject;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.PopControl;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.ca.sdk.EnrollCertsRequest;
import org.xipki.ca.sdk.EnrollOrPollCertsResponse;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.PollCertRequest;
import org.xipki.ca.sdk.SdkClient;
import org.xipki.ca.sdk.SdkErrorResponseException;
import org.xipki.ca.sdk.X500NameType;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.cms.CmsAlgorithm;
import org.xipki.pkix.cms.CmsException;
import org.xipki.pkix.cms.CmsSignedData;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.auth.Requestor;
import org.xipki.pkix.auth.RequestorAuthenticator;
import org.xipki.pkix.exception.ErrorCode;
import org.xipki.pkix.exception.OperationException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.message.CaCaps;
import org.xipki.pkix.scep.message.DecodedPkiMessage;
import org.xipki.pkix.scep.message.PkiMessage;
import org.xipki.pkix.scep.transaction.CaCapability;
import org.xipki.pkix.scep.transaction.FailInfo;
import org.xipki.pkix.scep.transaction.MessageType;
import org.xipki.pkix.scep.transaction.Nonce;
import org.xipki.pkix.scep.transaction.Operation;
import org.xipki.pkix.scep.transaction.PkiStatus;
import org.xipki.pkix.scep.util.ScepUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.audit.AuditLevel;
import org.xipki.util.audit.AuditService;
import org.xipki.util.audit.AuditStatus;
import org.xipki.util.audit.Audits;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.util.misc.EmbedCertsMode;
import org.xipki.pkix.util.misc.StringUtil;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Optional;

import static org.xipki.pkix.exception.ErrorCode.BAD_CERT_TEMPLATE;
import static org.xipki.pkix.exception.ErrorCode.NOT_PERMITTED;
import static org.xipki.pkix.exception.ErrorCode.PATH_NOT_FOUND;
import static org.xipki.pkix.exception.ErrorCode.SYSTEM_FAILURE;

/**
 * SCEP Responder.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepResponder {

  private static final String NAME_decryption = "decryption";

  private static final String NAME_fail_info = "fail_info";

  private static final String NAME_failure_message = "failure_message";

  private static final String NAME_message_type = "message_type";

  private static final String NAME_pki_status = "pki_status";

  private static final String NAME_signature = "signature";

  private static class FailInfoException extends Exception {

    public static final FailInfoException BAD_CERTID = new FailInfoException(FailInfo.badCertId);

    public static final FailInfoException BAD_MESSAGE_CHECK =
        new FailInfoException(FailInfo.badMessageCheck);

    public static final FailInfoException BAD_REQUEST = new FailInfoException(FailInfo.badRequest);

    private final FailInfo failInfo;

    private FailInfoException(FailInfo failInfo) {
      super(Args.notNull(failInfo, "failInfo").name());
      this.failInfo = failInfo;
    }

    public FailInfo failInfo() {
      return failInfo;
    }

  } // method FailInfoException

  private static final Logger LOG = LoggerFactory.getLogger(ScepResponder.class);

  private static final String CGI_PROGRAM = "/pkiclient.exe";

  private static final int CGI_PROGRAM_LEN = CGI_PROGRAM.length();

  private static final String CT_RESPONSE = ScepUtil.CT_PKI_MESSAGE;

  private final ScepControl control;

  private final SdkClient sdk;

  private final PopControl popControl;

  private final GatewayConf.CaProfilesControl caProfilesControl;

  private final CaCaps caCaps;

  private final SecurityFactory securityFactory;

  private final RequestorAuthenticator authenticator;

  private final CaNameScepSigners signers;

  public ScepResponder(
      ScepControl control, SdkClient sdk, SecurityFactory securityFactory,
      CaNameScepSigners signers, RequestorAuthenticator authenticator,
      PopControl popControl, GatewayConf.CaProfilesControl caProfiles) {
    this.control = Args.notNull(control, "control");
    this.sdk = Args.notNull(sdk, "sdk");
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
    this.authenticator = Args.notNull(authenticator, "authenticator");
    this.popControl = Args.notNull(popControl, "popControl");

    // CACaps
    CaCaps caps = new CaCaps();
    caps.addCapabilities(CaCapability.SCEPStandard, CaCapability.AES,
        CaCapability.DES3, CaCapability.POSTPKIOperation, CaCapability.Renewal,
        CaCapability.SHA1, CaCapability.SHA256, CaCapability.SHA512);
    this.caCaps = caps;
    this.signers = signers;

    this.caProfilesControl = Args.notNull(caProfiles, "caProfiles");
  } // constructor

  private CaCaps caCaps() {
    return caCaps;
  }

  private Requestor.PasswordRequestor getRequestor(String user) {
    return authenticator.getPasswordRequestorByUser(Requestor.Protocol.SCEP, user);
  }

  private Requestor.CertRequestor getRequestor(X509Cert cert) {
    return authenticator.getCertRequestor(Requestor.Protocol.SCEP, cert);
  }

  public HttpResponse service(String path, byte[] request, XiHttpRequest metadataRetriever) {
    String caName = null;
    String certprofileName = null;
    if (path.length() > 1) {
      if (path.endsWith(CGI_PROGRAM)) {
        String[] tokens;
        if (path.length() == CGI_PROGRAM_LEN) {
          tokens = new String[0];
        } else {
          // skip also the first char (which is always '/')
          String tpath = path.substring(1, path.length() - CGI_PROGRAM_LEN);
          tokens = StringUtil.splitAsArray(tpath, "/");
        }

        assert tokens != null;
        if (tokens.length == 0 || tokens.length == 1) {
          String alias = tokens.length == 0 ? "default" : tokens[0].trim();
          GatewayConf.CaProfileConf caProfileConf = caProfilesControl.getCaProfile(alias);
          if (caProfileConf == null) {
            LOG.warn("unknown alias {}", alias);
            return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
          }

          caName = caProfileConf.ca();
          certprofileName = caProfileConf.certprofile();
        } else if (tokens.length == 2) {
          caName = tokens[0];
          certprofileName = tokens[1].toLowerCase();
        }
      } // end if
    } // end if

    if (caName == null) {
      return new HttpResponse(HttpStatusCode.SC_NOT_FOUND);
    }

    AuditService auditService = Audits.getAuditService();
    AuditEvent event = new AuditEvent("scep-gw");
    event.addEventData("name", caName + "/" + certprofileName);

    AuditLevel auditLevel = AuditLevel.INFO;
    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
    String auditMessage = null;

    String operation = metadataRetriever.getParameter("operation");
    event.addEventData("operation", operation);

    HttpResponse ret;

    try {
      byte[] respBody;
      String contentType;

      if ("PKIOperation".equalsIgnoreCase(operation)) {
        CmsSignedData reqMessage;
        // parse the request
        try {
          reqMessage = new CmsSignedData(request);
        } catch (Exception ex) {
          final String msg = "invalid request";
          LogUtil.error(LOG, ex, msg);
          auditMessage = msg;
          auditStatus = AuditStatus.FAILED;
          return new HttpResponse(HttpStatusCode.SC_BAD_REQUEST);
        }

        ScepSigner signer = signers.getSigner(caName);
        if (signer == null) {
          final String msg = "found no signer";
          LOG.error(msg + " for CA {}", caName);
          auditMessage = msg;
          auditStatus = AuditStatus.FAILED;
          return new HttpResponse(HttpStatusCode.SC_BAD_REQUEST);
        }

        ContentInfo ci;
        try {
          ci = servicePkiOperation(signer, caName, reqMessage, certprofileName, event);
        } catch (CodecException ex) {
          final String msg = "could not decrypt and/or verify the request";
          LogUtil.error(LOG, ex, msg);
          auditMessage = msg;
          auditStatus = AuditStatus.FAILED;
          return new HttpResponse(HttpStatusCode.SC_BAD_REQUEST);
        } catch (OperationException | SdkErrorResponseException ex) {
          ErrorCode code;
          if (ex instanceof OperationException) {
            auditMessage = ex.getMessage();
            code = ((OperationException) ex).errorCode();
          } else {
            ErrorResponse err = ((SdkErrorResponseException) ex).errorResponse();
            auditMessage = err.message();
            code = err.code();
          }

          int httpCode;
          switch (code) {
            case ALREADY_ISSUED:
            case CERT_REVOKED:
            case CERT_UNREVOKED:
              httpCode = HttpStatusCode.SC_FORBIDDEN;
              break;
            case BAD_CERT_TEMPLATE:
            case BAD_REQUEST:
            case BAD_POP:
            case INVALID_EXTENSION:
            case UNKNOWN_CERT:
            case UNKNOWN_CERT_PROFILE:
              httpCode = HttpStatusCode.SC_BAD_REQUEST;
              break;
            case NOT_PERMITTED:
              httpCode = HttpStatusCode.SC_UNAUTHORIZED;
              break;
            case SYSTEM_UNAVAILABLE:
              httpCode = HttpStatusCode.SC_SERVICE_UNAVAILABLE;
              break;
            case CRL_FAILURE:
            case DATABASE_FAILURE:
            case SYSTEM_FAILURE:
            default:
              httpCode = HttpStatusCode.SC_INTERNAL_SERVER_ERROR;
              break;
          }

          LogUtil.error(LOG, ex, auditMessage);
          auditStatus = AuditStatus.FAILED;
          return new HttpResponse(httpCode);
        }

        respBody = ci.getEncoded();
        contentType = CT_RESPONSE;
      } else if (Operation.GetCACaps.code().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        contentType = ScepUtil.CT_TEXT_PLAIN;
        respBody = caCaps().bytes();
      } else if (Operation.GetCACert.code().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        contentType = ScepUtil.CT_X509_CA_RA_CERT;
        respBody = getCaCertResp(caName);
      } else if (Operation.GetNextCACert.code().equalsIgnoreCase(operation)) {
        auditMessage = "SCEP operation '" + operation + "' is not permitted";
        auditStatus = AuditStatus.FAILED;
        return new HttpResponse(HttpStatusCode.SC_FORBIDDEN);
      } else {
        auditMessage = "unknown SCEP operation '" + operation + "'";
        auditStatus = AuditStatus.FAILED;
        return new HttpResponse(HttpStatusCode.SC_BAD_REQUEST);
      }
      ret = new HttpResponse(HttpStatusCode.SC_OK, contentType, null, respBody);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);

      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
      auditMessage = "internal error";
      ret = new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    } finally {
      audit(auditService, event, auditLevel, auditStatus, auditMessage);
    }

    return ret;
  } // method service0

  private static void audit(
      AuditService auditService, AuditEvent event, AuditLevel auditLevel,
      AuditStatus auditStatus, String auditMessage) {
    AuditLevel curLevel = event.level();
    if (curLevel == null || curLevel.value() > auditLevel.value()) {
      event.setLevel(auditLevel);
    }

    if (auditStatus != null) {
      event.setStatus(auditStatus);
    }

    if (auditMessage != null) {
      event.addEventData(CaAuditConstants.NAME_message, auditMessage);
    }

    event.finish();
    auditService.logEvent(event);

    GatewayUtil.logAuditEvent(LOG, event);
  } // method audit

  private byte[] getCaCertResp(String caName)
      throws OperationException, SdkErrorResponseException {
    try {
      ScepSigner signer = Optional.ofNullable(signers.getSigner(caName)).orElseThrow(
          () -> new OperationException(PATH_NOT_FOUND, "found no signer for CA " + caName));

      byte[] cacert = Optional.ofNullable(sdk.cacert(caName)).orElseThrow(
          () -> new OperationException(PATH_NOT_FOUND, "unknown CA " + caName));

      CmsSignedData.Builder cmsSignedDataGen = new CmsSignedData.Builder();
      try {
        cmsSignedDataGen.addCertificate(Certificate.fromEncoded(cacert));
        cmsSignedDataGen.addCertificate(signer.cert().getCert());
        // separate RA certificate for the encryption, selected by the client via keyUsage
        cmsSignedDataGen.addCertificate(signer.encryptionCert().getCert());
        CmsSignedData degenerateSignedData = cmsSignedDataGen.build();
        return degenerateSignedData.getEncoded();
      } catch (CodecException ex) {
        throw new CmsException("could not build CMS SignedDta");
      }
    } catch (CmsException ex) {
      throw new OperationException(SYSTEM_FAILURE, ex.getMessage());
    }
  }

  private ContentInfo servicePkiOperation(
      ScepSigner signer, String caName, CmsSignedData requestContent, String certprofileName,
      AuditEvent event) throws CodecException, OperationException, SdkErrorResponseException {
    DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, signer.decryptor(), null);
    PkiMessage rep = servicePkiOperation0(caName, requestContent, req, certprofileName, event);

    audit(event, NAME_pki_status, rep.pkiStatus().toString());

    if (rep.pkiStatus() == PkiStatus.FAILURE) {
      event.setStatus(AuditStatus.FAILED);
    }

    if (rep.failInfo() != null) {
      audit(event, NAME_fail_info, rep.failInfo().toString());
    }

    return encodeResponse(signer, rep, req);
  } // method servicePkiOperation

  private PkiMessage servicePkiOperation0(
      String caName, CmsSignedData requestContent, DecodedPkiMessage req, String certprofileName,
      AuditEvent event) throws OperationException, SdkErrorResponseException {
    Args.notNull(requestContent, "requestContent");

    String tid = Args.notNull(req, "req").transactionId().id();
    // verify and decrypt the request
    audit(event, CaAuditConstants.NAME_tid, tid);

    if (req.failureMessage() != null) {
      audit(event, NAME_failure_message, req.failureMessage());
    }

    if (!dfltTrue(req.isSignatureValid())) {
      audit(event, NAME_signature, "invalid");
    }

    if (!dfltTrue(req.isDecryptionSuccessful())) {
      audit(event, NAME_decryption, "failed");
    }

    PkiMessage rep = new PkiMessage(req.transactionId(), MessageType.CertRep, Nonce.randomNonce());
    rep.setRecipientNonce(req.senderNonce());

    if (req.failureMessage() != null) {
      return fail(rep, FailInfo.badRequest);
    }

    if (!dfltTrue(req.isSignatureValid())) {
      return fail(rep, FailInfo.badMessageCheck);
    }

    if (!dfltTrue(req.isDecryptionSuccessful())) {
      return fail(rep, FailInfo.badRequest);
    }

    Instant signingTime = req.signingTime();
    long maxSigningTimeBiasInMs = 1000L * control.maxSigningTimeBias();
    if (maxSigningTimeBiasInMs > 0) {
      boolean isTimeBad = signingTime == null ||
          Math.abs(Instant.now().toEpochMilli() - signingTime.toEpochMilli())
              > maxSigningTimeBiasInMs;

      if (isTimeBad) {
        return fail(rep, FailInfo.badTime);
      }
    } // end if

    // check the digest algorithm
    HashAlgo hashAlgo = req.digestAlgorithm();
    boolean supported = false;
    if (hashAlgo == HashAlgo.SHA1) {
      if (caCaps.supportsSHA1()) {
        supported = true;
      }
    } else if (hashAlgo == HashAlgo.SHA256) {
      if (caCaps.supportsSHA256()) {
        supported = true;
      }
    } else if (hashAlgo == HashAlgo.SHA512) {
      if (caCaps.supportsSHA512()) {
        supported = true;
      }
    }

    if (!supported) {
      LOG.warn("tid={}: unsupported digest algorithm {}", tid, hashAlgo);
      return fail(rep, FailInfo.badAlg);
    }

    // check the content encryption algorithm
    Asn1Oid encOid = req.contentEncryptionAlgorithm();
    if (CmsAlgorithm.DES_EDE3_CBC.equals(encOid)) {
      if (!caCaps.supportsDES3()) {
        LOG.warn("tid={}: encryption with DES3 algorithm {} is not permitted", tid, encOid);
        return fail(rep, FailInfo.badAlg);
      }
    } else if (CmsAlgorithm.AES128_CBC.equals(encOid)) {
      if (!caCaps.supportsAES()) {
        LOG.warn("tid={}: encryption with AES algorithm {} is not permitted", tid, encOid);
        return fail(rep, FailInfo.badAlg);
      }
    } else {
      LOG.warn("tid={}: encryption with algorithm {} is not permitted", tid, encOid);
      return fail(rep, FailInfo.badAlg);
    }

    try {
      SignedData signedData;

      MessageType mt = req.messageType();
      audit(event, NAME_message_type, mt.toString());

      Requestor requestor = null;

      switch (mt) {
        case PKCSReq:
        case RenewalReq: {
          CertificationRequest csr;
          try {
            csr = GatewayUtil.parseCsrInRequest(req.messageData().asSequence());
          } catch (CodecException ex) {
            LOG.warn("tid={} parsing CSR failed", tid);
             throw FailInfoException.BAD_REQUEST;
          }

          X500Name reqSubject = csr.getCertificationRequestInfo().getSubject();
          if (LOG.isInfoEnabled()) {
            LOG.info("tid={}, subject={}", tid, X509Util.x500NameText(reqSubject));
          }

          event.addEventData(CaAuditConstants.NAME_certprofile, certprofileName);
          event.addEventData(CaAuditConstants.NAME_req_subject,
              "\"" + X509Util.x500NameText(reqSubject) + "\"");

          if (!GatewayUtil.verifyCsr(csr, securityFactory, popControl)) {
            LOG.warn("tid={} POP verification failed", tid);
            throw FailInfoException.BAD_MESSAGE_CHECK;
          }

          X509Cert reqSignatureCert = req.signatureCert();

          if (reqSignatureCert.isSelfSigned()) {
            if (!reqSignatureCert.subject().equals(csr.getSubject())) {
              LOG.warn("tid={}, self-signed identityCert.subject ({}) != csr.subject ({})",
                  tid, reqSignatureCert.subject(), csr.getSubject());
              throw FailInfoException.BAD_REQUEST;
            }
          }

          if (X509Util.getCommonName(csr.getSubject()) == null) {
            throw new OperationException(BAD_CERT_TEMPLATE, "tid=" + tid +
                ": no CommonName in requested subject");
          }

          String challengePwd = csr.challengePassword();
          if (challengePwd != null) {
            // user must not contain ':', the password may contain it.
            String[] strs = challengePwd.split(":", 2);
            if (strs.length != 2 || strs[0].isEmpty()) {
              LOG.warn("tid={}: challengePassword does not have the format <user>:<password>", tid);
              throw FailInfoException.BAD_REQUEST;
            }

            String user = strs[0];
            String password = strs[1];
            Requestor.PasswordRequestor requestor0 = getRequestor(user);
            requestor = requestor0;

            boolean authorized = requestor0 != null
                && requestor0.authenticate(password.getBytes(StandardCharsets.UTF_8));
            if (!authorized) {
              LOG.warn("tid={}: could not authenticate user {}", tid, user);
              throw FailInfoException.BAD_REQUEST;
            }
          } // end if

          if (reqSignatureCert.isSelfSigned()) {
            if (MessageType.PKCSReq != mt) {
              LOG.warn("tid={}: self-signed certificate is not permitted for messageType {}",
                  tid, mt);
              throw FailInfoException.BAD_REQUEST;
            }

            if (requestor == null) {
              LOG.warn("tid={}: could not extract user & password from challengePassword, which " +
                  "are required for self-signed signature certificate", tid);
              throw FailInfoException.BAD_REQUEST;
            }
          } else {
            // No challengePassword is sent, try to find out whether the
            // signature certificate is known by the CA
            if (requestor == null) {
              // up to draft-nourse-scep-23 the client sends all messages to
              // enroll certificate via MessageType PKCSReq
              requestor = getRequestor(reqSignatureCert);
              if (requestor == null) {
                LOG.warn("tid={}: signature certificate is not trusted by the CA", tid);
                throw FailInfoException.BAD_REQUEST;
              }
            } // end if
          } // end if

          checkUserPermission(requestor, caName, certprofileName);

          Extensions extensions = csr.getExtensionRequest();
          // need to remove the password
          EnrollCertsRequest.Entry template = new EnrollCertsRequest.Entry();
          template.setCertprofile(certprofileName);
          template.setSubject(new X500NameType(csr.getSubject()));

          template.extensions(extensions);
          template.subjectPublicKey(csr.getSubjectPKInfo());

          EnrollCertsRequest sdkReq = new EnrollCertsRequest();
          sdkReq.setEntries(new EnrollCertsRequest.Entry[]{template});
          sdkReq.setTransactionId(tid);
          sdkReq.setExplicitConfirm(false);
          EmbedCertsMode certsMode =
                control.isIncludeCertChain() ? EmbedCertsMode.CHAIN
              : control.isIncludeCaCert()    ? EmbedCertsMode.CERT  : EmbedCertsMode.NONE;
          sdkReq.setCaCertMode(certsMode);

          signedData = buildSignedData(sdk.enrollCerts(caName, sdkReq));
          break;
        }
        case CertPoll: {
          IssuerAndSubject is;
          try {
            is = IssuerAndSubject.fromAsn1(req.messageData().asSequence());
          } catch (CodecException e) {
            LogUtil.warn(LOG, e, "could not parse IssuerAndSubject");
            throw FailInfoException.BAD_REQUEST;
          }

          audit(event, CaAuditConstants.NAME_issuer,
              "\"" + X509Util.x500NameText(is.getIssuer()) + "\"");
          audit(event, CaAuditConstants.NAME_subject,
              "\"" + X509Util.x500NameText(is.getSubject()) + "\"");
          PollCertRequest.Entry template = new PollCertRequest.Entry(null,
              new X500NameType(is.getSubject()));

          PollCertRequest sdkReq = new PollCertRequest(null,
              new X500NameType(is.getIssuer()), null,
              req.transactionId().id(), new PollCertRequest.Entry[]{template});

          signedData = buildSignedData(sdk.pollCerts(sdkReq));
          break;
        }
        case GetCert: {
          IssuerAndSerialNumber isn;
          try {
            isn = IssuerAndSerialNumber.fromAsn1(req.messageData().asSequence());
          } catch (CodecException e) {
            LogUtil.warn(LOG, e, "could not parse IssuerAndSerialNumber");
            throw FailInfoException.BAD_REQUEST;
          }

          BigInteger serial = isn.serialNumber();
          audit(event, CaAuditConstants.NAME_issuer,
              "\"" + X509Util.x500NameText(isn.getName()) + "\"");

          audit(event, CaAuditConstants.NAME_serial, LogUtil.formatCsn(serial));
          signedData = getCert(caName, isn.getName(), serial);
          break;
        }
        case GetCRL: {
          IssuerAndSerialNumber isn;
          try {
            isn = IssuerAndSerialNumber.fromAsn1(req.messageData().asSequence());
          } catch (CodecException e) {
            LogUtil.warn(LOG, e, "could not parse IssuerAndSerialNumber");
            throw FailInfoException.BAD_REQUEST;
          }

          BigInteger serial = isn.serialNumber();
          audit(event, CaAuditConstants.NAME_issuer,
              "\"" + X509Util.x500NameText(isn.getName()) + "\"");

          audit(event, CaAuditConstants.NAME_serial, LogUtil.formatCsn(serial));
          signedData = getCrl(caName, isn.getName(), serial);
          break;
        }
        default:
          LOG.error("unknown SCEP messageType '{}'", req.messageType());
          throw FailInfoException.BAD_REQUEST;
      } // end switch

      rep.setMessageData(ContentInfo.build(CmsOIDs.signedData, signedData));
      rep.setPkiStatus(PkiStatus.SUCCESS);
      return rep;
    } catch (FailInfoException ex) {
      LogUtil.error(LOG, ex);
      return fail(rep, ex.failInfo());
    }
  } // method servicePkiOperation0

  private SignedData getCert(String caName, X500Name issuer, BigInteger serialNumber)
      throws FailInfoException, OperationException, SdkErrorResponseException {
    byte[] encodedCert = Optional.ofNullable(sdk.getCert(caName, issuer, serialNumber))
        .orElseThrow(() -> FailInfoException.BAD_CERTID);

    return buildSignedData(encodedCert, null);
  } // method getCert

  private SignedData buildSignedData(EnrollOrPollCertsResponse sdkResp) throws OperationException {
    EnrollOrPollCertsResponse.Entry[] entries = sdkResp.entries();
    int n = entries == null ? 0 : entries.length;
    if (n != 1) {
      throw new OperationException(SYSTEM_FAILURE, "expected 1 cert, but received " + n);
    }

    EnrollOrPollCertsResponse.Entry entry = entries[0];
    byte[] cert = Optional.ofNullable(entry.cert()).orElseThrow(() ->
        new OperationException(ErrorCode.ofCode(entry.error().code()),
            "expected 1 cert, but received none"));

    return buildSignedData(cert, sdkResp.extraCerts());
  }

  private SignedData buildSignedData(byte[] cert, byte[][] extraCerts) throws OperationException {
    CmsSignedData.Builder cmsSignedDataGen = new CmsSignedData.Builder();
    try {
      cmsSignedDataGen.addCertificate(Certificate.fromEncoded(cert));

      if (extraCerts != null) {
        for (byte[] c : extraCerts) {
          cmsSignedDataGen.addCertificate(Certificate.fromEncoded(c));
        }
      }

      CmsSignedData csd = cmsSignedDataGen.build();
      return csd.getSignedData();
    } catch (CmsException | CodecException ex) {
      LogUtil.error(LOG, ex);
      throw new OperationException(SYSTEM_FAILURE, ex);
    }
  } // method buildSignedData

  private SignedData getCrl(String caName, X500Name issuer, BigInteger serialNumber)
      throws FailInfoException, OperationException, SdkErrorResponseException {
    if (!control.isSupportGetCrl()) {
      throw FailInfoException.BAD_REQUEST;
    }

    byte[] crl = sdk.currentCrl(caName);
    if (crl == null) {
      LOG.error("found no CRL");
      throw FailInfoException.BAD_REQUEST;
    }

    try {
      CmsSignedData.Builder cmsSignedDataGen = new CmsSignedData.Builder();
      cmsSignedDataGen.addCRL(CertificateList.fromEncoded(crl));
      CmsSignedData signedData = cmsSignedDataGen.build();
      return signedData.getSignedData();
    } catch (CmsException | CodecException ex) {
      LogUtil.error(LOG, ex, "could not generate CMSSignedData");
      throw new OperationException(SYSTEM_FAILURE, ex);
    }
  } // method getCrl

  private ContentInfo encodeResponse(
      ScepSigner signer, PkiMessage response, DecodedPkiMessage request) throws OperationException {
    Args.notNull(response, "response");
    Args.notNull(request, "request");

    String algorithm = signer.key().getAlgorithm();

    if (!"RSA".equalsIgnoreCase(algorithm)) {
      throw new UnsupportedOperationException(
          "getSignatureAlgorithm() for non-RSA is not supported yet.");
    }

    HashAlgo hashAlgo = request.digestAlgorithm();

    try {
      SignAlgo signatureAlgorithm = SignAlgo.getInstance(hashAlgo.jceName() + "withRSA");
      X509Cert[] cmsCertSet = control.isIncludeSignerCert() ? new X509Cert[]{signer.cert()} : null;

      return response.encode(signer.key(), signatureAlgorithm, signer.cert(), cmsCertSet,
            request.signatureCert(), request.contentEncryptionAlgorithm());
    } catch (CodecException | NoSuchAlgorithmException ex) {
      LogUtil.error(LOG, ex, "could not encode response");
      throw new OperationException(SYSTEM_FAILURE, ex);
    }
  } // method encodeResponse

  private static void checkUserPermission(Requestor requestor, String caName, String certprofile)
      throws OperationException {
    Requestor.Permission permission = Requestor.Permission.ENROLL_CERT;
    if (!requestor.isPermitted(permission)) {
      throw new OperationException(NOT_PERMITTED,
          permission + " is not permitted for user " + requestor.name());
    }

    if (!requestor.isCertprofilePermitted(caName, certprofile)) {
      throw new OperationException(NOT_PERMITTED,
          "Certificate profile " + certprofile + " is not permitted for user " + requestor.name());
    }
  } // method checkUserPermission

  private static void audit(AuditEvent audit, String name, String value) {
    audit.addEventData(name, (value == null) ? "null" : value);
  }

  private static PkiMessage fail(PkiMessage rep, FailInfo failInfo) {
    rep.setPkiStatus(PkiStatus.FAILURE);
    rep.setFailInfo(failInfo);
    return rep;
  }

  private static boolean dfltTrue(Boolean b) {
    return b == null || b;
  }

}
