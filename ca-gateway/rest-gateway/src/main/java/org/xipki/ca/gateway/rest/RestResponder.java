// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.rest;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.gateway.*;
import org.xipki.ca.sdk.*;
import org.xipki.security.CrlReason;
import org.xipki.security.SecurityFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.HttpRequestMetadataRetriever;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.PemEncoder.PemLabel;
import org.xipki.util.exception.ErrorCode;
import org.xipki.util.exception.OperationException;
import org.xipki.util.http.HttpRespContent;

import java.io.*;
import java.math.BigInteger;
import java.time.Instant;
import java.util.*;

import static org.xipki.audit.AuditLevel.ERROR;
import static org.xipki.audit.AuditLevel.INFO;
import static org.xipki.audit.AuditStatus.FAILED;
import static org.xipki.audit.AuditStatus.SUCCESSFUL;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.exception.ErrorCode.*;

/**
 * REST API responder.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class RestResponder {

  private static class HttpRespAuditException extends Exception {

    private final int httpStatus;

    private final String auditMessage;

    private final AuditLevel auditLevel;

    private final AuditStatus auditStatus;

    public HttpRespAuditException(int httpStatus, String auditMessage, AuditLevel auditLevel, AuditStatus auditStatus) {
      this.httpStatus = httpStatus;
      this.auditMessage = Args.notBlank(auditMessage, "auditMessage");
      this.auditLevel = Args.notNull(auditLevel, "auditLevel");
      this.auditStatus = Args.notNull(auditStatus, "auditStatus");
    }

    public int getHttpStatus() {
      return httpStatus;
    }

    public String getAuditMessage() {
      return auditMessage;
    }

    public AuditLevel getAuditLevel() {
      return auditLevel;
    }

    public AuditStatus getAuditStatus() {
      return auditStatus;
    }

  } // class HttpRespAuditException

  final byte[] NEWLINE = new byte[]{'\r', '\n'};

  private static final int OK = 200;

  private static final int BAD_REQUEST = 400;

  private static final int UNAUTHORIZED = 401;

  private static final int NOT_FOUND = 404;

  private static final int CONFLICT = 409;

  private static final int UNSUPPORTED_MEDIA_TYPE = 415;

  private static final int INTERNAL_SERVER_ERROR = 500;

  private static final int SERVICE_UNAVAILABLE = 503;

  private static final String CT_pkcs10 = "application/pkcs10";

  private static final String CT_pkix_crl = "application/pkix-crl";

  private static final String CT_pkix_cert = "application/pkix-cert";

  private static final String CT_pem_file = "application/x-pem-file";

  private static final String HEADER_PKISTATUS = "X-xipki-pkistatus";

  private static final String PKISTATUS_accepted = "accepted";

  private static final String PKISTATUS_rejection = "rejection";

  private static final String HEADER_failInfo = "X-xipki-fail-info";

  private static final String FAILINFO_badRequest = "badRequest";

  private static final String FAILINFO_badCertId = "badCertId";

  private static final String FAILINFO_badPOP = "badPOP";

  private static final String FAILINFO_certRevoked = "certRevoked";

  private static final String FAILINFO_badCertTemplate = "badCertTemplate";

  private static final String FAILINFO_notAuthorized = "notAuthorized";

  private static final String FAILINFO_systemUnavail = "systemUnavail";

  private static final String FAILINFO_systemFailure = "systemFailure";

  private static final String CMD_cacert = "cacert";

  private static final String CMD_cacerts = "cacerts";

  private static final String CMD_revoke_cert = "revoke-cert";

  private static final String CMD_unsuspend_cert = "unsuspend-cert";

  @Deprecated
  private static final String CMD_unrevoke_cert = "unrevoke-cert";

  private static final String CMD_enroll_cert = "enroll-cert";

  private static final String CMD_enroll_cross_cert = "enroll-cross-cert";

  private static final String CMD_enroll_serverkeygen = "enroll-serverkeygen";

  private static final String CMD_enroll_cert_twin = "enroll-cert-twin";

  private static final String CMD_enroll_serverkeygen_twin = "enroll-serverkeygen-twin";

  private static final String CMD_crl = "crl";

  private static final String PARAM_profile = "profile";

  private static final String PARAM_reason = "reason";

  private static final String PARAM_not_before = "not-before";

  private static final String PARAM_not_after = "not-after";

  private static final String PARAM_invalidity_time = "invalidity-time";

  private static final String PARAM_crl_number = "crl-number";

  private static final String PARAM_ca_sha1 = "ca-sha1";

  private static final String PARAM_serial_number = "serial-number";

  private static final Logger LOG = LoggerFactory.getLogger(RestResponder.class);

  private final SdkClient sdk;

  private final SecurityFactory securityFactory;

  private final PopControl popControl;

  private final RequestorAuthenticator authenticator;

  private static final Set<String> knownCommands;

  static {
    knownCommands = CollectionUtil.asUnmodifiableSet(
        CMD_cacert, CMD_cacerts, CMD_revoke_cert, CMD_unsuspend_cert, CMD_unrevoke_cert, CMD_enroll_cert,
        CMD_enroll_cross_cert, CMD_enroll_serverkeygen, CMD_enroll_cert_twin, CMD_enroll_serverkeygen_twin, CMD_crl);
  }

  public RestResponder(SdkClient sdk, SecurityFactory securityFactory,
                       RequestorAuthenticator authenticator, PopControl popControl) {
    this.sdk = notNull(sdk, "sdk");
    this.securityFactory = notNull(securityFactory, "securityFactory");
    this.authenticator = notNull(authenticator, "authenticator");
    this.popControl = notNull(popControl, "popControl");
  }

  private Requestor getRequestor(String user) {
    return authenticator.getPasswordRequestorByUser(user);
  }

  private Requestor getRequestor(X509Cert cert) {
    return authenticator.getCertRequestor(cert);
  }

  public RestResponse service(
      String path, byte[] request, HttpRequestMetadataRetriever httpRetriever, AuditEvent event) {
    AuditLevel auditLevel = INFO;
    AuditStatus auditStatus = SUCCESSFUL;
    String auditMessage = null;

    try {
      String caName = null;
      String command = null;

      if (path.length() > 1) {
        // the first char is always '/'
        String coreUri = path;
        int sepIndex = coreUri.indexOf('/', 1);
        if (sepIndex == -1 || sepIndex == coreUri.length() - 1) {
          String message = "invalid path " + path;
          LOG.error(message);
          throw new HttpRespAuditException(NOT_FOUND, message, ERROR, FAILED);
        }

        // skip also the first char ('/')
        caName = coreUri.substring(1, sepIndex).toLowerCase();
        command = coreUri.substring(sepIndex + 1).toLowerCase();
      }

      if (StringUtil.isBlank(command)) {
        String message = "command is not specified";
        LOG.warn(message);
        throw new HttpRespAuditException(NOT_FOUND, message, INFO, FAILED);
      }

      if (StringUtil.isBlank(caName)) {
        String message = "CA is not specified";
        LOG.warn(message);
        throw new HttpRespAuditException(NOT_FOUND, message, INFO, FAILED);
      }

      event.addEventData(CaAuditConstants.NAME_ca, caName);
      event.addEventType(command);

      if (!knownCommands.contains(command)) {
        String message = "invalid command '" + command + "'";
        LOG.error(message);
        throw new HttpRespAuditException(NOT_FOUND, message, INFO, FAILED);
      }

      if (CMD_cacert.equals(command)) {
        return toRestResponse(HttpRespContent.ofOk(CT_pkix_cert, sdk.cacert(caName)));
      } else if (CMD_cacerts.equals(command)) {
        byte[][] certsBytes = sdk.cacerts(caName);
        return toRestResponse(HttpRespContent.ofOk(CT_pem_file,
            StringUtil.toUtf8Bytes(X509Util.encodeCertificates(certsBytes))));
      } else if (CMD_crl.equals(command)) {
        return toRestResponse(getCrl(caName, httpRetriever));
      }

      Requestor requestor;
      // Retrieve the user:password
      String hdrValue = httpRetriever.getHeader("Authorization");
      if (hdrValue != null && hdrValue.startsWith("Basic ")) {
        String user = null;
        byte[] password = null;
        if (hdrValue.length() > 6) {
          String b64 = hdrValue.substring(6);
          byte[] userPwd = Base64.decodeFast(b64);
          int idx = -1;
          for (int i = 0; i < userPwd.length; i++) {
            if (userPwd[i] == ':') {
              idx = i;
              break;
            }
          }

          if (idx != -1 && idx < userPwd.length - 1) {
            user = StringUtil.toUtf8String(Arrays.copyOfRange(userPwd, 0, idx));
            password = Arrays.copyOfRange(userPwd, idx + 1, userPwd.length);
          }
        }

        if (user == null) {
          throw new HttpRespAuditException(UNAUTHORIZED, "invalid Authorization information", INFO, FAILED);
        }

        requestor = getRequestor(user);
        boolean authorized = requestor != null && requestor.authenticate(password);
        if (!authorized) {
          throw new HttpRespAuditException(UNAUTHORIZED, "could not authenticate user " + user, INFO, FAILED);
        }
      } else {
        X509Cert clientCert = httpRetriever.getTlsClientCert();
        if (clientCert == null) {
          throw new HttpRespAuditException(UNAUTHORIZED, "no client certificate", INFO, FAILED);
        }
        requestor = getRequestor(clientCert);

        if (requestor == null) {
          throw new OperationException(NOT_PERMITTED, "no requestor specified");
        }
      }

      event.addEventData(CaAuditConstants.NAME_requestor, requestor.getName());

      HttpRespContent respContent;

      switch (command) {
        case CMD_enroll_cross_cert:
          respContent = enrollCrossCert(caName, requestor, request, httpRetriever, event);
          break;
        case CMD_enroll_cert:
        case CMD_enroll_serverkeygen:
        case CMD_enroll_cert_twin:
        case CMD_enroll_serverkeygen_twin:
          respContent = enrollCerts(command, caName, requestor, request, httpRetriever, event);
          break;
        case CMD_revoke_cert:
        case CMD_unsuspend_cert:
        case CMD_unrevoke_cert:
          unRevoke(command, caName, requestor, httpRetriever, event);
          respContent = null;
          break;
        default:
          throw new IllegalStateException("invalid command '" + command + "'"); // should not reach here
      }

      return toRestResponse(respContent);
    } catch (OperationException ex) {
      ErrorCode code = ex.getErrorCode();
      if (LOG.isWarnEnabled()) {
        String msg = StringUtil.concat("generate certificate, OperationException: code=",
            code.name(), ", message=", ex.getErrorMessage());
        LogUtil.warn(LOG, ex, msg);
      }

      int sc;
      String failureInfo;
      switch (code) {
        case ALREADY_ISSUED:
        case BAD_REQUEST:
        case INVALID_EXTENSION:
        case UNKNOWN_CERT_PROFILE:
        case CERT_UNREVOKED:
          sc = BAD_REQUEST;
          failureInfo = FAILINFO_badRequest;
          break;
        case BAD_CERT_TEMPLATE:
          sc = BAD_REQUEST;
          failureInfo = FAILINFO_badCertTemplate;
          break;
        case CERT_REVOKED:
          sc = CONFLICT;
          failureInfo = FAILINFO_certRevoked;
          break;
        case NOT_PERMITTED:
        case UNAUTHORIZED:
          sc = UNAUTHORIZED;
          failureInfo = FAILINFO_notAuthorized;
          break;
        case SYSTEM_UNAVAILABLE:
          sc = SERVICE_UNAVAILABLE;
          failureInfo = FAILINFO_systemUnavail;
          break;
        case UNKNOWN_CERT:
          sc = BAD_REQUEST;
          failureInfo = FAILINFO_badCertId;
          break;
        case BAD_POP:
          sc = BAD_REQUEST;
          failureInfo = FAILINFO_badPOP;
          break;
        case PATH_NOT_FOUND:
          sc = NOT_FOUND;
          failureInfo = FAILINFO_systemUnavail;
          break;
        case CRL_FAILURE:
        case DATABASE_FAILURE:
        case SYSTEM_FAILURE:
        default:
          sc = INTERNAL_SERVER_ERROR;
          failureInfo = FAILINFO_systemFailure;
          break;
      } // end switch (code)

      event.setStatus(FAILED);
      event.addEventData(CaAuditConstants.NAME_message, code.name());

      auditMessage = code.name();
      if (code != DATABASE_FAILURE && code != SYSTEM_FAILURE) {
        auditMessage += ": " + ex.getErrorMessage();
      }

      Map<String, String> headers = new HashMap<>();
      headers.put(HEADER_PKISTATUS, PKISTATUS_rejection);

      if (StringUtil.isNotBlank(failureInfo)) {
        headers.put(HEADER_failInfo, failureInfo);
      }
      return new RestResponse(sc, null, headers, null);
    } catch (HttpRespAuditException ex) {
      auditStatus = ex.getAuditStatus();
      auditLevel = ex.getAuditLevel();
      auditMessage = ex.getAuditMessage();
      return new RestResponse(ex.getHttpStatus(), null, null, null);
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }
      auditLevel = ERROR;
      auditStatus = FAILED;
      auditMessage = "internal error";
      return new RestResponse(INTERNAL_SERVER_ERROR, null, null, null);
    } finally {
      event.setStatus(auditStatus);
      event.setLevel(auditLevel);
      if (auditMessage != null) {
        event.addEventData(CaAuditConstants.NAME_message, auditMessage);
      }
    }
  } // method service

  private RestResponse toRestResponse(HttpRespContent respContent) {
    Map<String, String> headers = new HashMap<>();
    headers.put(HEADER_PKISTATUS, PKISTATUS_accepted);

    return (respContent == null) ? new RestResponse(OK, null, headers, null)
        : new RestResponse(OK, respContent.getContentType(), headers, respContent.isBase64(), respContent.getContent());
  }

  private HttpRespContent enrollCerts(
      String command, String caName, Requestor requestor, byte[] request,
      HttpRequestMetadataRetriever httpRetriever, AuditEvent event)
      throws HttpRespAuditException, OperationException, IOException, SdkErrorResponseException {
    if (!requestor.isPermitted(PermissionConstants.ENROLL_CERT)) {
      throw new OperationException(NOT_PERMITTED, "ENROLL_CERT is not allowed");
    }

    boolean twin = CMD_enroll_cert_twin.equals(command) || CMD_enroll_serverkeygen_twin.equals(command);
    boolean caGenKeyPair = CMD_enroll_serverkeygen.equals(command) || CMD_enroll_serverkeygen_twin.equals(command);

    String profile = checkProfile(requestor, httpRetriever);

    String profileEnc = twin ? profile + "-enc" : null;
    if (profileEnc != null && !requestor.isCertprofilePermitted(profileEnc)) {
      throw new OperationException(NOT_PERMITTED, "certprofile " + profileEnc + " is not allowed");
    }

    String strNotBefore = httpRetriever.getParameter(PARAM_not_before);
    Instant notBefore = (strNotBefore == null) ? null :  DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotBefore);

    String strNotAfter = httpRetriever.getParameter(PARAM_not_after);
    Instant notAfter = (strNotAfter == null) ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotAfter);

    X500Name subject;
    Extensions extensions;
    SubjectPublicKeyInfo subjectPublicKeyInfo;

    String ct = httpRetriever.getHeader("Content-Type");
    if (caGenKeyPair) {
      subjectPublicKeyInfo = null;

      if (ct.startsWith("text/plain")) {
        Properties props = new Properties();
        props.load(new ByteArrayInputStream(request));
        String strSubject = props.getProperty("subject");
        if (strSubject == null) {
          throw new OperationException(BAD_CERT_TEMPLATE, "subject is not specified");
        }

        try {
          subject = new X500Name(strSubject);
        } catch (Exception ex) {
          throw new OperationException(BAD_CERT_TEMPLATE, "invalid subject");
        }
        extensions = null;
      } else if (CT_pkcs10.equalsIgnoreCase(ct)) {
        // some clients may send the PEM encoded CSR.
        request = X509Util.toDerEncoded(request);

        // The PKCS#10 will only be used for transport of subject and extensions.
        // The associated key will not be used, so the verification of POP is skipped.
        CertificationRequestInfo certTemp = CertificationRequest.getInstance(request).getCertificationRequestInfo();
        subject = certTemp.getSubject();
        extensions = X509Util.getExtensions(certTemp);
      } else {
        throw new HttpRespAuditException(UNSUPPORTED_MEDIA_TYPE, "unsupported media type " + ct, INFO, FAILED);
      }
    } else {
      if (!CT_pkcs10.equalsIgnoreCase(ct)) {
        throw new HttpRespAuditException(UNSUPPORTED_MEDIA_TYPE, "unsupported media type " + ct, INFO, FAILED);
      }

      CertificationRequest csr = CertificationRequest.getInstance(request);
      if (!GatewayUtil.verifyCsr(csr, securityFactory, popControl)) {
        throw new OperationException(BAD_POP);
      }

      CertificationRequestInfo certTemp = csr.getCertificationRequestInfo();

      subject = certTemp.getSubject();
      subjectPublicKeyInfo = certTemp.getSubjectPublicKeyInfo();
      extensions = X509Util.getExtensions(certTemp);
    }

    BigInteger certId = BigInteger.ONE;
    BigInteger certIdEnc = twin ? BigInteger.valueOf(2) : null;

    EnrollCertRequestEntry template = new EnrollCertRequestEntry();
    template.setCertReqId(certId);
    template.setCertprofile(profile);
    template.setSubject(new X500NameType(subject));
    template.notBefore(notBefore);
    template.notAfter(notAfter);

    event.addEventData(CaAuditConstants.NAME_certprofile, profile);
    event.addEventData(CaAuditConstants.NAME_req_subject, "\"" + X509Util.x500NameText(subject) + "\"");

    try {
      template.extensions(extensions);
    } catch (IOException e) {
      String message  ="could not encode extensions";
      throw new HttpRespAuditException(BAD_REQUEST, message, INFO, FAILED);
    }

    try {
      template.subjectPublicKey(subjectPublicKeyInfo);
    } catch (IOException e) {
      String message  ="could not encode SubjectPublicKeyInfo";
      throw new HttpRespAuditException(BAD_REQUEST, message, INFO, FAILED);
    }

    List<EnrollCertRequestEntry> templates = new ArrayList<>(twin ? 2 : 1);
    templates.add(template);

    if (twin) {
      template = new EnrollCertRequestEntry();
      template.setCertReqId(certIdEnc);
      template.setCertprofile(profileEnc);
      template.setSubject(new X500NameType(subject));
      template.notBefore(notBefore);
      template.notAfter(notAfter);

      event.addEventData(CaAuditConstants.NAME_certprofile, profileEnc);
      event.addEventData(CaAuditConstants.NAME_req_subject, "\"" + X509Util.x500NameText(subject) + "\"");

      try {
        template.extensions(extensions);
      } catch (IOException e) {
        String message  ="could not encode extensions";
        throw new HttpRespAuditException(BAD_REQUEST, message, INFO, FAILED);
      }

      templates.add(template);
    }

    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setEntries(templates);
    sdkReq.setExplicitConfirm(false);
    sdkReq.setGroupEnroll(twin);
    sdkReq.setCaCertMode(CertsMode.NONE);

    EnrollOrPollCertsResponse sdkResp = sdk.enrollCerts(caName, sdkReq);
    checkResponse(templates.size(), sdkResp);

    EnrollOrPullCertResponseEntry entry = getEntry(sdkResp.getEntries(), certId);
    if (!(caGenKeyPair || twin)) {
      return HttpRespContent.ofOk(CT_pkix_cert, entry.getCert());
    }

    ByteArrayOutputStream bo = new ByteArrayOutputStream();

    if (caGenKeyPair) {
      bo.write(PemEncoder.encode(entry.getPrivateKey(), PemLabel.PRIVATE_KEY));
      bo.write(NEWLINE);
    }

    bo.write(PemEncoder.encode(entry.getCert(), PemLabel.CERTIFICATE));
    bo.write(NEWLINE);

    if (twin) {
      entry = getEntry(sdkResp.getEntries(), certIdEnc);

      bo.write(PemEncoder.encode(entry.getPrivateKey(), PemLabel.PRIVATE_KEY));
      bo.write(NEWLINE);

      bo.write(PemEncoder.encode(entry.getCert(), PemLabel.CERTIFICATE));
      bo.write(NEWLINE);
    }
    bo.flush();

    return HttpRespContent.ofOk(CT_pem_file, bo.toByteArray());
  }

  private HttpRespContent enrollCrossCert(
      String caName, Requestor requestor, byte[] request, HttpRequestMetadataRetriever httpRetriever, AuditEvent event)
      throws HttpRespAuditException, OperationException, IOException, SdkErrorResponseException {
    if (!requestor.isPermitted(PermissionConstants.ENROLL_CROSS)) {
      throw new OperationException(NOT_PERMITTED, "ENROLL_CROSS is not allowed");
    }

    String profile = checkProfile(requestor, httpRetriever);

    String ct = httpRetriever.getHeader("Content-Type");
    if (!CT_pem_file.equalsIgnoreCase(ct)) {
      String message = "unsupported media type " + ct;
      throw new HttpRespAuditException(UNSUPPORTED_MEDIA_TYPE, message, INFO, FAILED);
    }

    String strNotBefore = httpRetriever.getParameter(PARAM_not_before);
    Instant notBefore = (strNotBefore == null) ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotBefore);

    String strNotAfter = httpRetriever.getParameter(PARAM_not_after);
    Instant notAfter = (strNotAfter == null) ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotAfter);

    byte[] csrBytes = null;
    byte[] targetCertBytes = null;

    try (PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(request)))) {
      while (true) {
        PemObject pemObject = pemReader.readPemObject();
        if (pemObject == null) {
          break;
        }

        String type = pemObject.getType();
        if (PemLabel.CERTIFICATE_REQUEST.getType().equals(type)) {
          if (csrBytes != null) {
            throw new HttpRespAuditException(BAD_REQUEST, "duplicated PEM CSRs", INFO, FAILED);
          }
          csrBytes = pemObject.getContent();
        } else if (PemLabel.CERTIFICATE.getType().equals(type)) {
          if (targetCertBytes != null) {
            throw new HttpRespAuditException(BAD_REQUEST, "duplicated PEM certificates", INFO, FAILED);
          }
          targetCertBytes = pemObject.getContent();
        } else {
          throw new HttpRespAuditException(BAD_REQUEST, "unknown PEM object type " + type, INFO, FAILED);
        }
      }
    }

    if (csrBytes == null) {
      throw new HttpRespAuditException(BAD_REQUEST, "PEM CSR is not specified", INFO, FAILED);
    }

    if (targetCertBytes == null) {
      throw new HttpRespAuditException(BAD_REQUEST, "PEM CERTIFICATE is not specified", INFO, FAILED);
    }

    CertificationRequest csr = CertificationRequest.getInstance(csrBytes);
    if (!GatewayUtil.verifyCsr(csr, securityFactory, popControl)) {
      throw new OperationException(BAD_POP);
    }

    Certificate targetCert = Certificate.getInstance(targetCertBytes);
    try {
      X509Util.assertCsrAndCertMatch(csr, targetCert, true);
    } catch (XiSecurityException ex) {
      throw new HttpRespAuditException(BAD_REQUEST, ex.getMessage(), INFO, FAILED);
    }

    SubjectPublicKeyInfo subjectPublicKeyInfo = targetCert.getSubjectPublicKeyInfo();
    Extensions extensions = targetCert.getTBSCertificate().getExtensions();
    X500Name subject = targetCert.getSubject();
    BigInteger certId = BigInteger.ONE;

    Instant targetCertEndDate = targetCert.getEndDate().getDate().toInstant();
    if (notAfter == null || notAfter.isAfter(targetCertEndDate)) {
      notAfter = targetCertEndDate;
    }

    EnrollCertRequestEntry template = new EnrollCertRequestEntry();
    template.setCertReqId(certId);
    template.setCertprofile(profile);
    template.setSubject(new X500NameType(subject));
    template.notBefore(notBefore);
    template.notAfter(notAfter);

    event.addEventData(CaAuditConstants.NAME_certprofile, profile);
    event.addEventData(CaAuditConstants.NAME_req_subject, "\"" + X509Util.x500NameText(subject) + "\"");

    try {
      template.extensions(extensions);
    } catch (IOException e) {
      String message  ="could not encode extensions";
      throw new HttpRespAuditException(BAD_REQUEST, message, INFO, FAILED);
    }

    try {
      template.subjectPublicKey(subjectPublicKeyInfo);
    } catch (IOException e) {
      String message  ="could not encode SubjectPublicKeyInfo";
      throw new HttpRespAuditException(BAD_REQUEST, message, INFO, FAILED);
    }

    List<EnrollCertRequestEntry> templates = Collections.singletonList(template);

    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setEntries(templates);
    sdkReq.setExplicitConfirm(false);
    sdkReq.setGroupEnroll(false);
    sdkReq.setCaCertMode(CertsMode.NONE);

    EnrollOrPollCertsResponse sdkResp = sdk.enrollCrossCerts(caName, sdkReq);
    checkResponse(templates.size(), sdkResp);

    EnrollOrPullCertResponseEntry entry = getEntry(sdkResp.getEntries(), certId);
    return HttpRespContent.ofOk(CT_pkix_cert, entry.getCert());
  }

  private static void checkResponse(int expectedSize, EnrollOrPollCertsResponse resp) throws HttpRespAuditException {
    List<EnrollOrPullCertResponseEntry> entries = resp.getEntries();
    if (entries != null) {
      for (EnrollOrPullCertResponseEntry entry : entries) {
        if (entry.getError() != null) {
          throw new HttpRespAuditException(INTERNAL_SERVER_ERROR, entry.getError().toString(), INFO, FAILED);
        }
      }
    }

    int n = entries == null ? 0 : entries.size();
    if (n != expectedSize) {
      throw new HttpRespAuditException(INTERNAL_SERVER_ERROR, "expected " + expectedSize + " cert, but received " + n,
          INFO, FAILED);
    }
  }

  private static String checkProfile(
      Requestor requestor, HttpRequestMetadataRetriever httpRetriever) throws HttpRespAuditException, OperationException {
    String profile = httpRetriever.getParameter(PARAM_profile);
    if (StringUtil.isBlank(profile)) {
      throw new HttpRespAuditException(BAD_REQUEST, "required parameter " + PARAM_profile + " not specified",
          INFO, FAILED);
    }
    profile = profile.toLowerCase();

    if (!requestor.isCertprofilePermitted(profile)) {
      throw new OperationException(NOT_PERMITTED, "certprofile " + profile + " is not allowed");
    }
    return profile;
  }

  private static EnrollOrPullCertResponseEntry getEntry(
      List<EnrollOrPullCertResponseEntry> entries, BigInteger certReqId)
      throws HttpRespAuditException {
    for (EnrollOrPullCertResponseEntry m : entries) {
      if (certReqId.equals(m.getId())) {
        return m;
      }
    }
    throw new HttpRespAuditException(INTERNAL_SERVER_ERROR, "found no response entry with certReqId " + certReqId,
        INFO, FAILED);
  }

  private void unRevoke(
      String command, String caName, Requestor requestor,HttpRequestMetadataRetriever httpRetriever, AuditEvent event)
      throws OperationException, HttpRespAuditException, IOException, SdkErrorResponseException {
    boolean revoke = command.equals(CMD_revoke_cert);
    int permission = revoke ? PermissionConstants.REVOKE_CERT : PermissionConstants.UNSUSPEND_CERT;
    if (!requestor.isPermitted(permission)) {
      throw new OperationException(NOT_PERMITTED, command + " is not allowed");
    }

    String strCaSha1 = httpRetriever.getParameter(PARAM_ca_sha1);
    if (StringUtil.isBlank(strCaSha1)) {
      throw new HttpRespAuditException(BAD_REQUEST, "required parameter " + PARAM_ca_sha1 + " not specified",
          INFO, FAILED);
    }
    byte[] caSha1 = Hex.decode(strCaSha1);

    String strSerialNumber = httpRetriever.getParameter(PARAM_serial_number);
    if (StringUtil.isBlank(strSerialNumber)) {
      throw new HttpRespAuditException(BAD_REQUEST, "required parameter " + PARAM_serial_number + " not specified",
          INFO, FAILED);
    }

    BigInteger serialNumber;
    try {
      serialNumber = StringUtil.toBigInt(strSerialNumber);
    } catch (NumberFormatException ex) {
      throw new OperationException(ErrorCode.BAD_REQUEST, ex.getMessage());
    }

    event.addEventData(CaAuditConstants.NAME_serial, LogUtil.formatCsn(serialNumber));

    if (!revoke) {
      UnsuspendOrRemoveRequest sdkReq = new UnsuspendOrRemoveRequest();
      sdkReq.setIssuerCertSha1Fp(caSha1);
      sdkReq.setEntries(Collections.singletonList(serialNumber));
      sdk.unsuspendCerts(caName, sdkReq);
    } else {
      String strReason = httpRetriever.getParameter(PARAM_reason);
      CrlReason reason = (strReason == null) ? CrlReason.UNSPECIFIED : CrlReason.forNameOrText(strReason);
      if (reason == CrlReason.REMOVE_FROM_CRL) {
        throw new OperationException(ErrorCode.BAD_REQUEST,
            "reason " + CrlReason.REMOVE_FROM_CRL.getDescription() + " is not allowed!");
      }
      event.addEventData(CaAuditConstants.NAME_reason, reason);

      Instant invalidityTime = null;
      String strInvalidityTime = httpRetriever.getParameter(PARAM_invalidity_time);
      if (StringUtil.isNotBlank(strInvalidityTime)) {
        invalidityTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(strInvalidityTime);
      }

      RevokeCertRequestEntry entry = new RevokeCertRequestEntry();
      entry.setSerialNumber(serialNumber);
      if (invalidityTime != null) {
        entry.setInvalidityTime(invalidityTime.getEpochSecond());
      }
      entry.setReason(reason);

      RevokeCertsRequest sdkReq = new RevokeCertsRequest();
      sdkReq.setIssuerCertSha1Fp(caSha1);
      sdkReq.setEntries(Collections.singletonList(entry));
      sdk.revokeCerts(caName, sdkReq);
    }
  }

  private HttpRespContent getCrl(String caName, HttpRequestMetadataRetriever httpRetriever)
      throws OperationException, HttpRespAuditException, IOException, SdkErrorResponseException {
    String strCrlNumber = httpRetriever.getParameter(PARAM_crl_number);
    BigInteger crlNumber = null;
    if (StringUtil.isNotBlank(strCrlNumber)) {
      try {
        crlNumber = StringUtil.toBigInt(strCrlNumber);
      } catch (NumberFormatException ex) {
        String message = "invalid crlNumber '" + strCrlNumber + "'";
        LOG.warn(message);
        throw new HttpRespAuditException(BAD_REQUEST, message, INFO, FAILED);
      }
    }

    byte[] respBytes = sdk.currentCrl(caName, crlNumber, null, null);
    if (respBytes == null) {
      String message = "could not get CRL";
      LOG.warn(message);
      throw new HttpRespAuditException(INTERNAL_SERVER_ERROR, message, INFO, FAILED);
    }

    return HttpRespContent.ofOk(CT_pkix_crl, respBytes);
  }

}
