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
import java.util.*;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.exception.ErrorCode.*;

/**
 * REST API responder.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public class RestResponder {

  private static class HttpRespAuditException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int httpStatus;

    private final String auditMessage;

    private final AuditLevel auditLevel;

    private final AuditStatus auditStatus;

    public HttpRespAuditException(int httpStatus, String auditMessage,
        AuditLevel auditLevel, AuditStatus auditStatus) {
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

  private static final Logger LOG = LoggerFactory.getLogger(RestResponder.class);

  private final SdkClient sdk;

  private final SecurityFactory securityFactory;

  private final PopControl popControl;

  private final RequestorAuthenticator authenticator;

  public RestResponder(
      SdkClient sdk, SecurityFactory securityFactory, RequestorAuthenticator authenticator, PopControl popControl) {
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
    event.setApplicationName(CaAuditConstants.APPNAME);
    event.setName(CaAuditConstants.NAME_perf);

    AuditLevel auditLevel = AuditLevel.INFO;
    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
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
          throw new HttpRespAuditException(NOT_FOUND, message, AuditLevel.ERROR, AuditStatus.FAILED);
        }

        // skip also the first char ('/')
        caName = coreUri.substring(1, sepIndex).toLowerCase();
        command = coreUri.substring(sepIndex + 1).toLowerCase();
      }

      if (StringUtil.isBlank(command)) {
        String message = "command is not specified";
        LOG.warn(message);
        throw new HttpRespAuditException(NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      if (StringUtil.isBlank(caName)) {
        String message = "CA is not specified";
        LOG.warn(message);
        throw new HttpRespAuditException(NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      event.addEventData(CaAuditConstants.NAME_ca, caName);
      event.addEventType(command);

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
          throw new HttpRespAuditException(UNAUTHORIZED, "invalid Authorization information",
              AuditLevel.INFO, AuditStatus.FAILED);
        }

        requestor = getRequestor(user);
        boolean authorized = requestor != null && requestor.authenticate(password);
        if (!authorized) {
          throw new HttpRespAuditException(UNAUTHORIZED, "could not authenticate user " + user,
              AuditLevel.INFO, AuditStatus.FAILED);
        }
      } else {
        X509Cert clientCert = httpRetriever.getTlsClientCert();
        if (clientCert == null) {
          throw new HttpRespAuditException(UNAUTHORIZED, "no client certificate", AuditLevel.INFO, AuditStatus.FAILED);
        }
        requestor = getRequestor(clientCert);

        if (requestor == null) {
          throw new OperationException(NOT_PERMITTED, "no requestor specified");
        }
      }

      event.addEventData(CaAuditConstants.NAME_requestor, requestor.getName());

      HttpRespContent respContent;

      switch (command) {
        case RestAPIConstants.CMD_cacert: {
          respContent = HttpRespContent.ofOk(RestAPIConstants.CT_pkix_cert, sdk.cacert(caName));
          break;
        }
        case RestAPIConstants.CMD_cacertchain: {
          byte[][] certsBytes = sdk.cacertchain(caName);
          respContent = HttpRespContent.ofOk(RestAPIConstants.CT_pem_file,
              StringUtil.toUtf8Bytes(X509Util.encodeCertificates(certsBytes)));
          break;
        }
        case RestAPIConstants.CMD_enroll_cross_cert: {
          respContent = enrollCrossCert(caName, requestor, request, httpRetriever, event);
          break;
        }
        case RestAPIConstants.CMD_enroll_cert:
        case RestAPIConstants.CMD_enroll_cert_genkey:
        case RestAPIConstants.CMD_enroll_cert_twin:
        case RestAPIConstants.CMD_enroll_cert_genkey_twin: {
          respContent = enrollCerts(command, caName, requestor, request, httpRetriever, event);
          break;
        }
        case RestAPIConstants.CMD_revoke_cert:
        case RestAPIConstants.CMD_unsuspend_cert:
        case RestAPIConstants.CMD_unrevoke_cert: {
          unRevoke(command, caName, requestor, httpRetriever, event);
          respContent = null;
          break;
        }
        case RestAPIConstants.CMD_crl: {
          respContent = getCrl(caName, requestor, httpRetriever);
          break;
        }
        default: {
          String message = "invalid command '" + command + "'";
          LOG.error(message);
          throw new HttpRespAuditException(NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
        }
      }

      Map<String, String> headers = new HashMap<>();
      headers.put(RestAPIConstants.HEADER_PKISTATUS, RestAPIConstants.PKISTATUS_accepted);
      if (respContent == null) {
        return new RestResponse(OK, null, headers, null);
      } else {
        return new RestResponse(OK, respContent.getContentType(), headers, respContent.getContent());
      }
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
          failureInfo = RestAPIConstants.FAILINFO_badRequest;
          break;
        case BAD_CERT_TEMPLATE:
          sc = BAD_REQUEST;
          failureInfo = RestAPIConstants.FAILINFO_badCertTemplate;
          break;
        case CERT_REVOKED:
          sc = CONFLICT;
          failureInfo = RestAPIConstants.FAILINFO_certRevoked;
          break;
        case NOT_PERMITTED:
        case UNAUTHORIZED:
          sc = UNAUTHORIZED;
          failureInfo = RestAPIConstants.FAILINFO_notAuthorized;
          break;
        case SYSTEM_UNAVAILABLE:
          sc = SERVICE_UNAVAILABLE;
          failureInfo = RestAPIConstants.FAILINFO_systemUnavail;
          break;
        case UNKNOWN_CERT:
          sc = BAD_REQUEST;
          failureInfo = RestAPIConstants.FAILINFO_badCertId;
          break;
        case BAD_POP:
          sc = BAD_REQUEST;
          failureInfo = RestAPIConstants.FAILINFO_badPOP;
          break;
        case PATH_NOT_FOUND:
          sc = NOT_FOUND;
          failureInfo = RestAPIConstants.FAILINFO_systemUnavail;
          break;
        case CRL_FAILURE:
        case DATABASE_FAILURE:
        case SYSTEM_FAILURE:
        default:
          sc = INTERNAL_SERVER_ERROR;
          failureInfo = RestAPIConstants.FAILINFO_systemFailure;
          break;
      } // end switch (code)

      event.setStatus(AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, code.name());

      if (code == DATABASE_FAILURE || code == SYSTEM_FAILURE) {
        auditMessage = code.name();
      } else {
        auditMessage = code.name() + ": " + ex.getErrorMessage();
      }

      Map<String, String> headers = new HashMap<>();
      headers.put(RestAPIConstants.HEADER_PKISTATUS, RestAPIConstants.PKISTATUS_rejection);

      if (StringUtil.isNotBlank(failureInfo)) {
        headers.put(RestAPIConstants.HEADER_failInfo, failureInfo);
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
      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
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

  private HttpRespContent enrollCerts(
      String command, String caName, Requestor requestor, byte[] request,
      HttpRequestMetadataRetriever httpRetriever, AuditEvent event)
      throws HttpRespAuditException, OperationException, IOException, SdkErrorResponseException {
    if (!requestor.isPermitted(PermissionConstants.ENROLL_CERT)) {
      throw new OperationException(NOT_PERMITTED, "ENROLL_CERT is not allowed");
    }

    boolean twin = RestAPIConstants.CMD_enroll_cert_twin.equals(command)
        || RestAPIConstants.CMD_enroll_cert_genkey_twin.equals(command);
    boolean caGenKeyPair = RestAPIConstants.CMD_enroll_cert_genkey.equals(command)
        || RestAPIConstants.CMD_enroll_cert_genkey_twin.equals(command);

    String profile = checkProfile(requestor, httpRetriever);

    String profileEnc = twin ? profile + "-enc" : null;
    if (profileEnc != null && !requestor.isCertprofilePermitted(profileEnc)) {
      throw new OperationException(NOT_PERMITTED, "certprofile " + profileEnc + " is not allowed");
    }

    String strNotBefore = httpRetriever.getParameter(RestAPIConstants.PARAM_not_before);
    Date notBefore = (strNotBefore == null) ? null :  DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotBefore);

    String strNotAfter = httpRetriever.getParameter(RestAPIConstants.PARAM_not_after);
    Date notAfter = (strNotAfter == null) ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotAfter);

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
      } else if (RestAPIConstants.CT_pkcs10.equalsIgnoreCase(ct)) {
        // some clients may send the PEM encoded CSR.
        request = X509Util.toDerEncoded(request);

        // The PKCS#10 will only be used for transport of subject and extensions.
        // The associated key will not be used, so the verification of POP is skipped.
        CertificationRequestInfo certTemp = CertificationRequest.getInstance(request).getCertificationRequestInfo();
        subject = certTemp.getSubject();
        extensions = X509Util.getExtensions(certTemp);
      } else {
        String message = "unsupported media type " + ct;
        throw new HttpRespAuditException(UNSUPPORTED_MEDIA_TYPE, message, AuditLevel.INFO, AuditStatus.FAILED);
      }
    } else {
      if (!RestAPIConstants.CT_pkcs10.equalsIgnoreCase(ct)) {
        String message = "unsupported media type " + ct;
        throw new HttpRespAuditException(UNSUPPORTED_MEDIA_TYPE, message, AuditLevel.INFO, AuditStatus.FAILED);
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
      throw new HttpRespAuditException(BAD_REQUEST, message, AuditLevel.INFO, AuditStatus.FAILED);
    }

    try {
      template.subjectPublicKey(subjectPublicKeyInfo);
    } catch (IOException e) {
      String message  ="could not encode SubjectPublicKeyInfo";
      throw new HttpRespAuditException(BAD_REQUEST, message, AuditLevel.INFO, AuditStatus.FAILED);
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
        throw new HttpRespAuditException(BAD_REQUEST, message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      templates.add(template);
    }

    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setEntries(templates);
    sdkReq.setExplicitConfirm(false);
    sdkReq.setGroupEnroll(twin);
    sdkReq.setCaCertMode(CertsMode.NONE);

    EnrollOrPollCertsResponse sdkResp = sdk.enrollCerts(caName, sdkReq);
    List<EnrollOrPullCertResponseEntry> entries = sdkResp.getEntries();
    int n = entries == null ? 0 : entries.size();
    if (n != templates.size()) {
      throw new HttpRespAuditException(INTERNAL_SERVER_ERROR,
          "expected " + templates.size() + " cert, but received " + n, AuditLevel.INFO, AuditStatus.FAILED);
    }

    EnrollOrPullCertResponseEntry entry = getEntry(entries, certId);
    if (!(caGenKeyPair || twin)) {
      return HttpRespContent.ofOk(RestAPIConstants.CT_pkix_cert, entry.getCert());
    }

    ByteArrayOutputStream bo = new ByteArrayOutputStream();
    bo.write(PemEncoder.encode(entry.getCert(), PemLabel.CERTIFICATE));
    bo.write(NEWLINE);

    if (caGenKeyPair) {
      bo.write(PemEncoder.encode(entry.getCert(), PemLabel.PRIVATE_KEY));
      bo.write(NEWLINE);
    }

    if (twin) {
      entry = getEntry(entries, certIdEnc);
      bo.write(PemEncoder.encode(entry.getCert(), PemLabel.CERTIFICATE));
      bo.write(NEWLINE);

      bo.write(PemEncoder.encode(entry.getCert(), PemLabel.PRIVATE_KEY));
      bo.write(NEWLINE);
    }
    bo.flush();

    return HttpRespContent.ofOk(RestAPIConstants.CT_pem_file, bo.toByteArray());
  }

  private HttpRespContent enrollCrossCert(
      String caName, Requestor requestor, byte[] request, HttpRequestMetadataRetriever httpRetriever, AuditEvent event)
      throws HttpRespAuditException, OperationException, IOException, SdkErrorResponseException {
    if (!requestor.isPermitted(PermissionConstants.ENROLL_CROSS)) {
      throw new OperationException(NOT_PERMITTED, "ENROLL_CROSS is not allowed");
    }

    String profile = checkProfile(requestor, httpRetriever);

    String ct = httpRetriever.getHeader("Content-Type");
    if (!RestAPIConstants.CT_pem_file.equalsIgnoreCase(ct)) {
      String message = "unsupported media type " + ct;
      throw new HttpRespAuditException(UNSUPPORTED_MEDIA_TYPE, message, AuditLevel.INFO, AuditStatus.FAILED);
    }

    String strNotBefore = httpRetriever.getParameter(RestAPIConstants.PARAM_not_before);
    Date notBefore = (strNotBefore == null) ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotBefore);

    String strNotAfter = httpRetriever.getParameter(RestAPIConstants.PARAM_not_after);
    Date notAfter = (strNotAfter == null) ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(strNotAfter);

    byte[] csrBytes = null;
    byte[] targetCertBytes = null;

    PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(request)));
    try {
      while (true) {
        PemObject pemObject = pemReader.readPemObject();
        if (pemObject == null) {
          break;
        }

        String type = pemObject.getType();
        if (PemLabel.CERTIFICATE_REQUEST.getType().equals(type)) {
          if (csrBytes != null) {
            throw new HttpRespAuditException(BAD_REQUEST, "duplicated PEM CSRs", AuditLevel.INFO, AuditStatus.FAILED);
          }
          csrBytes = pemObject.getContent();
        } else if (PemLabel.CERTIFICATE.getType().equals(type)) {
          if (targetCertBytes != null) {
            throw new HttpRespAuditException(BAD_REQUEST, "duplicated PEM certificates",
                AuditLevel.INFO, AuditStatus.FAILED);
          }
          targetCertBytes = pemObject.getContent();
        } else {
          throw new HttpRespAuditException(BAD_REQUEST, "unknown PEM object type " + type,
              AuditLevel.INFO, AuditStatus.FAILED);
        }
      }
    } finally {
      pemReader.close();
    }

    if (csrBytes == null) {
      throw new HttpRespAuditException(BAD_REQUEST, "PEM CSR is not specified", AuditLevel.INFO, AuditStatus.FAILED);
    }

    if (targetCertBytes == null) {
      throw new HttpRespAuditException(BAD_REQUEST, "PEM CERTIFICATE is not specified",
          AuditLevel.INFO, AuditStatus.FAILED);
    }

    CertificationRequest csr = CertificationRequest.getInstance(csrBytes);
    if (!GatewayUtil.verifyCsr(csr, securityFactory, popControl)) {
      throw new OperationException(BAD_POP);
    }

    Certificate targetCert = Certificate.getInstance(targetCertBytes);
    try {
      X509Util.assertCsrAndCertMatch(csr, targetCert, true);
    } catch (XiSecurityException ex) {
      throw new HttpRespAuditException(BAD_REQUEST, ex.getMessage(), AuditLevel.INFO, AuditStatus.FAILED);
    }

    SubjectPublicKeyInfo subjectPublicKeyInfo = targetCert.getSubjectPublicKeyInfo();
    Extensions extensions = targetCert.getTBSCertificate().getExtensions();
    X500Name subject = targetCert.getSubject();
    BigInteger certId = BigInteger.ONE;
    if (notAfter == null || notAfter.after(targetCert.getEndDate().getDate())) {
      notAfter = targetCert.getEndDate().getDate();
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
      throw new HttpRespAuditException(BAD_REQUEST, message, AuditLevel.INFO, AuditStatus.FAILED);
    }

    try {
      template.subjectPublicKey(subjectPublicKeyInfo);
    } catch (IOException e) {
      String message  ="could not encode SubjectPublicKeyInfo";
      throw new HttpRespAuditException(BAD_REQUEST, message, AuditLevel.INFO, AuditStatus.FAILED);
    }

    List<EnrollCertRequestEntry> templates = Collections.singletonList(template);

    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setEntries(templates);
    sdkReq.setExplicitConfirm(false);
    sdkReq.setGroupEnroll(false);
    sdkReq.setCaCertMode(CertsMode.NONE);

    EnrollOrPollCertsResponse sdkResp = sdk.enrollCrossCerts(caName, sdkReq);
    List<EnrollOrPullCertResponseEntry> entries = sdkResp.getEntries();
    int n = entries == null ? 0 : entries.size();
    if (n != templates.size()) {
      throw new HttpRespAuditException(INTERNAL_SERVER_ERROR,
          "expected " + templates.size() + " cert, but received " + n, AuditLevel.INFO, AuditStatus.FAILED);
    }

    EnrollOrPullCertResponseEntry entry = getEntry(entries, certId);
    return HttpRespContent.ofOk(RestAPIConstants.CT_pkix_cert, entry.getCert());
  }

  private static String checkProfile(
      Requestor requestor, HttpRequestMetadataRetriever httpRetriever) throws HttpRespAuditException, OperationException {
    String profile = httpRetriever.getParameter(RestAPIConstants.PARAM_profile);
    if (StringUtil.isBlank(profile)) {
      throw new HttpRespAuditException(BAD_REQUEST,
          "required parameter " + RestAPIConstants.PARAM_profile + " not specified",
          AuditLevel.INFO, AuditStatus.FAILED);
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
    throw new HttpRespAuditException(INTERNAL_SERVER_ERROR,
        "found no response entry with certReqId " + certReqId, AuditLevel.INFO, AuditStatus.FAILED);
  }

  private void unRevoke(
      String command, String caName, Requestor requestor,HttpRequestMetadataRetriever httpRetriever, AuditEvent event)
      throws OperationException, HttpRespAuditException, IOException, SdkErrorResponseException {
    boolean revoke = command.equals(RestAPIConstants.CMD_revoke_cert);
    int permission = revoke ? PermissionConstants.REVOKE_CERT : PermissionConstants.UNSUSPEND_CERT;
    if (!requestor.isPermitted(permission)) {
      throw new OperationException(NOT_PERMITTED, command + " is not allowed");
    }

    String strCaSha1 = httpRetriever.getParameter(RestAPIConstants.PARAM_ca_sha1);
    if (StringUtil.isBlank(strCaSha1)) {
      throw new HttpRespAuditException(BAD_REQUEST,
          "required parameter " + RestAPIConstants.PARAM_ca_sha1 + " not specified",
          AuditLevel.INFO, AuditStatus.FAILED);
    }
    byte[] caSha1 = Hex.decode(strCaSha1);

    String strSerialNumber = httpRetriever.getParameter(RestAPIConstants.PARAM_serial_number);
    if (StringUtil.isBlank(strSerialNumber)) {
      throw new HttpRespAuditException(BAD_REQUEST,
          "required parameter " + RestAPIConstants.PARAM_serial_number + " not specified",
          AuditLevel.INFO, AuditStatus.FAILED);
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
      String strReason = httpRetriever.getParameter(RestAPIConstants.PARAM_reason);
      CrlReason reason = (strReason == null) ? CrlReason.UNSPECIFIED : CrlReason.forNameOrText(strReason);
      if (reason == CrlReason.REMOVE_FROM_CRL) {
        throw new OperationException(ErrorCode.BAD_REQUEST,
            "reason " + CrlReason.REMOVE_FROM_CRL.getDescription() + " is not allowed!");
      }
      event.addEventData(CaAuditConstants.NAME_reason, reason);

      Date invalidityTime = null;
      String strInvalidityTime = httpRetriever.getParameter(RestAPIConstants.PARAM_invalidity_time);
      if (StringUtil.isNotBlank(strInvalidityTime)) {
        invalidityTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(strInvalidityTime);
      }

      RevokeCertRequestEntry entry = new RevokeCertRequestEntry();
      entry.setSerialNumber(serialNumber);
      if (invalidityTime != null) {
        entry.setInvalidityTime(invalidityTime.getTime() / 1000);
      }
      entry.setReason(reason);

      RevokeCertsRequest sdkReq = new RevokeCertsRequest();
      sdkReq.setIssuerCertSha1Fp(caSha1);
      sdkReq.setEntries(Collections.singletonList(entry));
      sdk.revokeCerts(caName, sdkReq);
    }
  }

  private HttpRespContent getCrl(
      String caName, Requestor requestor, HttpRequestMetadataRetriever httpRetriever)
      throws OperationException, HttpRespAuditException, IOException, SdkErrorResponseException {
    if (!requestor.isPermitted(PermissionConstants.GET_CRL)) {
      throw new OperationException(NOT_PERMITTED, "GET_CRL is not allowed");
    }

    String strCrlNumber = httpRetriever.getParameter(RestAPIConstants.PARAM_crl_number);
    BigInteger crlNumber = null;
    if (StringUtil.isNotBlank(strCrlNumber)) {
      try {
        crlNumber = StringUtil.toBigInt(strCrlNumber);
      } catch (NumberFormatException ex) {
        String message = "invalid crlNumber '" + strCrlNumber + "'";
        LOG.warn(message);
        throw new HttpRespAuditException(BAD_REQUEST, message, AuditLevel.INFO, AuditStatus.FAILED);
      }
    }

    byte[] respBytes = sdk.currentCrl(caName, crlNumber, null, null);
    if (respBytes == null) {
      String message = "could not get CRL";
      LOG.warn(message);
      throw new HttpRespAuditException(INTERNAL_SERVER_ERROR, message, AuditLevel.INFO, AuditStatus.FAILED);
    }

    return HttpRespContent.ofOk(RestAPIConstants.CT_pkix_crl, respBytes);
  }

}
