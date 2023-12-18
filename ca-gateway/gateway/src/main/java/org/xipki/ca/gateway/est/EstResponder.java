// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.est;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.PopControl;
import org.xipki.ca.gateway.api.Requestor;
import org.xipki.ca.gateway.api.RequestorAuthenticator;
import org.xipki.ca.gateway.conf.CaProfileConf;
import org.xipki.ca.gateway.conf.CaProfilesControl;
import org.xipki.ca.sdk.*;
import org.xipki.pki.ErrorCode;
import org.xipki.pki.OperationException;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.util.TlsHelper;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.http.HttpRespContent;
import org.xipki.util.http.HttpResponse;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.util.http.XiHttpRequest;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.*;

/**
 * EST responder.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class EstResponder {

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

  private static final byte[] NEWLINE = new byte[]{'\r', '\n'};

  private static final byte[] __NEWLINE = new byte[]{'-', '-', '\r', '\n'};

  private static final String CMD_cacerts = "cacerts";

  private static final String CMD_simpleenroll = "simpleenroll";

  private static final String CMD_simplereenroll = "simplereenroll";

  private static final String CMD_serverkeygen = "serverkeygen";

  /**
   * XiPKI own command. The response returns the CA's certificate as raw certificate.
   */
  private static final String CMD_ucacert = "ucacert";

  /**
   * XiPKI own command. Same as cacerts, but returns the CA's certificates in a PEM file.
   */
  private static final String CMD_ucacerts = "ucacerts";

  /**
   * XiPKI own command. Returns the raw CRL.
   */
  private static final String CMD_ucrl = "ucrl";

  /**
   * XiPKI own command. Same as simpleenroll, but returns the raw certificate.
   */
  private static final String CMD_usimpleenroll = "usimpleenroll";

  /**
   * XiPKI own command. Same as simplereenroll, but returns the raw certificate.
   */
  private static final String CMD_usimplereenroll = "usimplereenroll";

  /**
   * XiPKI own command. Same as serverkeygen, but returns the raw certificate in the certificate part.
   */
  private static final String CMD_userverkeygen = "userverkeygen";

  private static final String CMD_csrattrs = "csrattrs";

  private static final String CMD_fullcmc = "fullcmc";

  private static final String CT_pkix_cert = "application/pkix-cert";

  private static final String CT_pkix_crl = "application/pkix-crl";

  private static final String CT_pkcs8 = "application/pkcs8";

  private static final String CT_pkcs10 = "application/pkcs10";

  private static final String CT_csrattrs = "application/csrattrs";

  private static final String CT_pkcs7_mime = "application/pkcs7-mime";

  private static final String CT_multipart_mixed = "multipart/mixed";

  private static final String CT_pkcs7_mime_certyonly = CT_pkcs7_mime + "; smime-type=certs-only";

  private static final String CT_pem_file = "application/x-pem-file";

  private static final Logger LOG = LoggerFactory.getLogger(EstResponder.class);

  private final String reverseProxyMode;

  private final SdkClient sdk;

  private final SecurityFactory securityFactory;

  private final CaProfilesControl caProfilesControl;

  private final PopControl popControl;

  private final RequestorAuthenticator authenticator;

  private final Random random = new Random();

  private static final Set<String> knownCommands;

  static {
    knownCommands = CollectionUtil.asUnmodifiableSet(
        CMD_cacerts, CMD_simpleenroll, CMD_simplereenroll, CMD_serverkeygen, CMD_cacerts, CMD_csrattrs, CMD_fullcmc,
        CMD_ucacerts, CMD_ucacert, CMD_ucrl, CMD_usimpleenroll, CMD_usimplereenroll, CMD_userverkeygen);
  }

  public EstResponder(
      SdkClient sdk, SecurityFactory securityFactory, RequestorAuthenticator authenticator,
      PopControl popControl, CaProfilesControl caProfiles, String reverseProxyMode) {
    this.sdk = Args.notNull(sdk, "sdk");
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
    this.authenticator = Args.notNull(authenticator, "authenticator");
    this.popControl = Args.notNull(popControl, "popControl");
    this.caProfilesControl = Args.notNull(caProfiles, "caProfiles");
    this.reverseProxyMode = reverseProxyMode;
  }

  private Requestor.PasswordRequestor getRequestor(String user) {
    return authenticator.getPasswordRequestorByUser(user);
  }

  private Requestor.CertRequestor getRequestor(X509Cert cert) {
    return authenticator.getCertRequestor(cert);
  }

  public HttpResponse service(
      String path, byte[] request, XiHttpRequest httpRequest, AuditEvent event) {
    AuditLevel auditLevel = AuditLevel.INFO;
    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
    String auditMessage = null;

    try {
      // the first char is always '/'
      String coreUri = path.substring(1);
      String[] tokens = StringUtil.splitAsArray(coreUri, "/");

      String caName;
      String profile;
      String command;
      if (tokens.length == 1 || tokens.length == 2) {
        String alias = tokens.length == 1 ? "default" : tokens[0].trim();
        CaProfileConf caProfileConf = caProfilesControl.getCaProfile(alias);
        if (caProfileConf == null) {
          String message = "unknown alias " + alias;
          LOG.warn(message);
          throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
        }

        caName = caProfileConf.getCa();
        profile = caProfileConf.getCertprofile();
      } else if (tokens.length == 3) {
        caName = tokens[0].toLowerCase(Locale.ROOT);
        profile = tokens[1].toLowerCase(Locale.ROOT);
      } else {
        String message = "invalid path " + path;
        LOG.error(message);
        throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message, AuditLevel.ERROR, AuditStatus.FAILED);
      }
      command = tokens[tokens.length - 1].toLowerCase(Locale.ROOT);

      if (StringUtil.isBlank(caName)) {
        String message = "CA is not specified";
        LOG.warn(message);
        throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      if (StringUtil.isBlank(profile)) {
        String message = "profile is not specified";
        LOG.warn(message);
        throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      if (StringUtil.isBlank(command)) {
        String message = "command is not specified";
        LOG.warn(message);
        throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      event.addEventData(CaAuditConstants.NAME_ca, caName);
      event.addEventType(command);

      if (!knownCommands.contains(command)) {
        String message = "invalid command '" + command + "'";
        LOG.error(message);
        throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      switch (command) {
        case CMD_cacerts: {
          byte[][] certsBytes = sdk.cacerts(caName);
          return toHttpResponse(HttpRespContent.ofOk(CT_pkcs7_mime, true, buildCertsOnly(certsBytes)));
        }
        case CMD_ucacerts: {
          byte[][] certsBytes = sdk.cacerts(caName);
          return toHttpResponse(HttpRespContent.ofOk(CT_pem_file,
              StringUtil.toUtf8Bytes(X509Util.encodeCertificates(certsBytes))));
        }
        case CMD_ucacert: {
          byte[] certBytes = sdk.cacert(caName);
          return toHttpResponse(HttpRespContent.ofOk(CT_pkix_cert, true, certBytes));
        }
        case CMD_ucrl: {
          byte[] crlBytes = sdk.currentCrl(caName);
          if (crlBytes == null) {
            String message = "could not get CRL";
            LOG.warn(message);
            throw new HttpRespAuditException(HttpStatusCode.SC_INTERNAL_SERVER_ERROR,
                message, AuditLevel.INFO, AuditStatus.FAILED);
          }

          return toHttpResponse(HttpRespContent.ofOk(CT_pkix_crl, true, crlBytes));
        }
        case CMD_csrattrs: {
          return toHttpResponse(getCsrAttrs(caName, profile));
        }
        case CMD_fullcmc: {
          String message = "supported command '" + command + "'";
          LOG.error(message);
          throw new HttpRespAuditException(HttpStatusCode.SC_NOT_FOUND, message, AuditLevel.INFO, AuditStatus.FAILED);
        }
      }

      Requestor requestor;
      // Retrieve the user:password
      String hdrValue = httpRequest.getHeader("Authorization");
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
          throw new HttpRespAuditException(HttpStatusCode.SC_UNAUTHORIZED, "invalid Authorization information",
              AuditLevel.INFO, AuditStatus.FAILED);
        }

        Requestor.PasswordRequestor requestor0 = getRequestor(user);
        requestor = requestor0;

        boolean authorized = requestor0 != null && requestor0.authenticate(password);
        if (!authorized) {
          throw new HttpRespAuditException(HttpStatusCode.SC_UNAUTHORIZED, "could not authenticate user " + user,
              AuditLevel.INFO, AuditStatus.FAILED);
        }
      } else {
        X509Cert clientCert = Optional.ofNullable(TlsHelper.getTlsClientCert(httpRequest, reverseProxyMode))
            .orElseThrow(() -> new HttpRespAuditException(
                HttpStatusCode.SC_UNAUTHORIZED, "no client certificate", AuditLevel.INFO, AuditStatus.FAILED));

        requestor = Optional.ofNullable(getRequestor(clientCert))
            .orElseThrow(() -> new OperationException(ErrorCode.NOT_PERMITTED, "no requestor specified"));
      }

      event.addEventData(CaAuditConstants.NAME_requestor, requestor.getName());

      String ct = httpRequest.getHeader("Content-Type");
      if (!CT_pkcs10.equalsIgnoreCase(ct)) {
        String message = "unsupported media type " + ct;
        throw new HttpRespAuditException(HttpStatusCode.SC_UNSUPPORTED_MEDIA_TYPE,
            message, AuditLevel.INFO, AuditStatus.FAILED);
      }

      if (!requestor.isPermitted(Requestor.Permission.ENROLL_CERT)) {
        throw new OperationException(ErrorCode.NOT_PERMITTED, "ENROLL_CERT is not allowed");
      }

      if (!requestor.isCertprofilePermitted(caName, profile)) {
        throw new OperationException(ErrorCode.NOT_PERMITTED, "certprofile " + profile + " is not allowed");
      }

      CertificationRequest csr = GatewayUtil.parseCsrInRequest(request);
      if (!CMD_serverkeygen.equals(command)) {
        if (!GatewayUtil.verifyCsr(csr, securityFactory, popControl)) {
          throw new OperationException(ErrorCode.BAD_POP);
        }
      }

      HttpRespContent respContent;
      if (CMD_simplereenroll.equals(command) || CMD_usimplereenroll.equals(command)) {
        respContent = reenrollCert(command, caName, profile, csr, event);
      } else {
        respContent = enrollCert(command, caName, profile, csr, event);
      }

      return toHttpResponse(respContent);
    } catch (OperationException ex) {
      ErrorCode code = ex.getErrorCode();
      if (LOG.isWarnEnabled()) {
        String msg = StringUtil.concat("generate certificate, OperationException: code=",
            code.name(), ", message=", ex.getErrorMessage());
        LogUtil.warn(LOG, ex, msg);
      }

      int sc;
      switch (code) {
        case ALREADY_ISSUED:
        case BAD_REQUEST:
        case INVALID_EXTENSION:
        case UNKNOWN_CERT_PROFILE:
        case CERT_UNREVOKED:
        case BAD_CERT_TEMPLATE:
        case UNKNOWN_CERT:
        case BAD_POP:
          sc = HttpStatusCode.SC_BAD_REQUEST;
          break;
        case CERT_REVOKED:
          sc = HttpStatusCode.SC_CONFLICT;
          break;
        case NOT_PERMITTED:
        case UNAUTHORIZED:
          sc = HttpStatusCode.SC_UNAUTHORIZED;
          break;
        case SYSTEM_UNAVAILABLE:
          sc = HttpStatusCode.SC_SERVICE_UNAVAILABLE;
          break;
        case PATH_NOT_FOUND:
          sc = HttpStatusCode.SC_NOT_FOUND;
          break;
        case CRL_FAILURE:
        case DATABASE_FAILURE:
        case SYSTEM_FAILURE:
        default:
          sc = HttpStatusCode.SC_INTERNAL_SERVER_ERROR;
          break;
      } // end switch (code)

      event.setStatus(AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, code.name());

      if (code == ErrorCode.DATABASE_FAILURE || code == ErrorCode.SYSTEM_FAILURE) {
        auditMessage = code.name();
      } else {
        auditMessage = code.name() + ": " + ex.getErrorMessage();
      }

      return new HttpResponse(sc);
    } catch (HttpRespAuditException ex) {
      auditStatus = ex.getAuditStatus();
      auditLevel = ex.getAuditLevel();
      auditMessage = ex.getAuditMessage();
      return new HttpResponse(ex.getHttpStatus());
    } catch (Throwable th) {
      if (th instanceof EOFException) {
        LogUtil.warn(LOG, th, "connection reset by peer");
      } else {
        LOG.error("Throwable thrown, this should not happen!", th);
      }
      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
      auditMessage = "internal error";
      return new HttpResponse(HttpStatusCode.SC_INTERNAL_SERVER_ERROR);
    } finally {
      event.setStatus(auditStatus);
      event.setLevel(auditLevel);
      if (auditMessage != null) {
        event.addEventData(CaAuditConstants.NAME_message, auditMessage);
      }
    }
  } // method service

  private HttpResponse toHttpResponse(HttpRespContent respContent) {
    return respContent == null
        ? new HttpResponse(HttpStatusCode.SC_OK)
        : new HttpResponse(HttpStatusCode.SC_OK, respContent.getContentType(), null,
              respContent.isBase64(), respContent.getContent());
  }

  private HttpRespContent enrollCert(
      String command, String caName, String profile, CertificationRequest csr, AuditEvent event)
      throws HttpRespAuditException, IOException, SdkErrorResponseException {
    boolean caGenKeyPair  = CMD_serverkeygen.equals(command) || CMD_userverkeygen.equals(command);

    CertificationRequestInfo certTemp = csr.getCertificationRequestInfo();
    X500Name subject = certTemp.getSubject();

    BigInteger reqId = BigInteger.ONE;
    EnrollCertsRequest.Entry template = new EnrollCertsRequest.Entry();
    template.setCertReqId(reqId);
    template.setCertprofile(profile);
    template.setSubject(new X500NameType(subject));

    event.addEventData(CaAuditConstants.NAME_certprofile, profile);
    event.addEventData(CaAuditConstants.NAME_req_subject, "\"" + X509Util.x500NameText(subject) + "\"");

    Extensions extensions = X509Util.getExtensions(certTemp);

    try {
      template.extensions(extensions);
    } catch (IOException e) {
      throw new HttpRespAuditException(HttpStatusCode.SC_BAD_REQUEST, "could not encode extensions",
          AuditLevel.INFO, AuditStatus.FAILED);
    }

    if (!caGenKeyPair) {
      try {
        template.subjectPublicKey(certTemp.getSubjectPublicKeyInfo());
      } catch (IOException e) {
        throw new HttpRespAuditException(HttpStatusCode.SC_BAD_REQUEST, "could not encode SubjectPublicKeyInfo",
            AuditLevel.INFO, AuditStatus.FAILED);
      }
    }

    EnrollCertsRequest.Entry[] templates = new EnrollCertsRequest.Entry[]{template};

    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setEntries(templates);
    sdkReq.setExplicitConfirm(false);
    sdkReq.setCaCertMode(CertsMode.NONE);

    EnrollOrPollCertsResponse sdkResp = sdk.enrollCerts(caName, sdkReq);
    checkResponse(1, sdkResp);

    EnrollOrPollCertsResponse.Entry entry = getEntry(sdkResp.getEntries(), reqId);
    if (!caGenKeyPair) {
      if (CMD_usimpleenroll.equals(command)) {
        return HttpRespContent.ofOk(CT_pkix_cert, true, entry.getCert());
      } else {
        return HttpRespContent.ofOk(CT_pkcs7_mime_certyonly, true, buildCertsOnly(entry.getCert()));
      }
    }

    if (CMD_userverkeygen.equals(command)) {
      try (ByteArrayOutputStream bo = new ByteArrayOutputStream()) {
        bo.write(PemEncoder.encode(entry.getPrivateKey(), PemEncoder.PemLabel.PRIVATE_KEY));
        bo.write(PemEncoder.encode(entry.getCert(), PemEncoder.PemLabel.CERTIFICATE));
        bo.flush();

        return HttpRespContent.ofOk(CT_pem_file, bo.toByteArray());
      }
    }

    byte[] t = new byte[9]; // length must be multiple of 3
    random.nextBytes(t);
    String boundary = "estBounary_" + Base64.encodeToString(t);
    byte[] boundaryBytes = StringUtil.toUtf8Bytes("--" + boundary);

    try (ByteArrayOutputStream bo = new ByteArrayOutputStream()) {
      writeLine(bo, "XiPKI EST server");

      // private key
      writeMultipartEntry(bo, boundaryBytes, CT_pkcs8, entry.getPrivateKey());

      // certificate
      byte[] certBytes = buildCertsOnly(entry.getCert());
      writeMultipartEntry(bo, boundaryBytes, CT_pkcs7_mime_certyonly, certBytes);

      // finalize the multipart
      bo.write(boundaryBytes);
      bo.write(__NEWLINE);

      bo.flush();

      return HttpRespContent.ofOk(CT_multipart_mixed + "; boundary=" + boundary, false, bo.toByteArray());
    }
  } // method enrollCert

  private static void writeMultipartEntry(OutputStream os, byte[] boundaryBytes, String ct, byte[] data)
      throws IOException {
    os.write(boundaryBytes);
    os.write(NEWLINE);
    writeLine(os, "Content-Type: " + ct);
    writeLine(os, "Content-Transfer-Encoding: base64");
    os.write(NEWLINE);
    os.write(Base64.encodeToByte(data, true));
    os.write(NEWLINE);
  }

  private HttpRespContent reenrollCert(
      String command, String caName, String profile, CertificationRequest csr, AuditEvent event)
      throws HttpRespAuditException, IOException, SdkErrorResponseException {
    CertificationRequestInfo certTemp = csr.getCertificationRequestInfo();

    event.addEventData(CaAuditConstants.NAME_certprofile, profile);
    X500Name oldSubject = certTemp.getSubject();

    BigInteger reqId = BigInteger.ONE;
    EnrollCertsRequest.Entry template = new EnrollCertsRequest.Entry();
    template.setCertReqId(reqId);
    template.setCertprofile(profile);

    try {
      template.subjectPublicKey(certTemp.getSubjectPublicKeyInfo());
    } catch (IOException e) {
      throw new HttpRespAuditException(HttpStatusCode.SC_BAD_REQUEST, "could not encode SubjectPublicKeyInfo",
          AuditLevel.INFO, AuditStatus.FAILED);
    }

    // set the oldCertInfo
    Extensions csrExtns = X509Util.getExtensions(certTemp);
    byte[] extnValue = X509Util.getCoreExtValue(csrExtns, Extension.subjectAlternativeName);

    OldCertInfo oldCertInfo = new OldCertInfo(false,
        new OldCertInfo.BySubject(oldSubject.getEncoded(), extnValue));

    template.setOldCertInfo(oldCertInfo);

    Attribute attr = X509Util.getAttribute(certTemp, ObjectIdentifiers.CMC.id_cmc_changeSubjectName);
    Extensions requestedExtns = csrExtns;
    X500Name requestedSubject = oldSubject;

    if (attr != null) {
      /*
        ChangeSubjectName ::= SEQUENCE {
          subject             Name OPTIONAL,
          subjectAlt          GeneralNames OPTIONAL
        }

        Name ::= CHOICE { -- only one possibility for now --
           rdnSequence  RDNSequence }

        RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

        RelativeDistinguishedName ::=
          SET SIZE (1..MAX) OF AttributeTypeAndValue

        GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
       */
      ASN1Sequence seq = ASN1Sequence.getInstance(attr.getAttributeValues()[0]);
      int size = seq.size();

      X500Name newSubject = null;
      GeneralNames newSubjectAlt = null;

      if (size == 2) {
        newSubject = X500Name.getInstance(seq.getObjectAt(0));
        newSubjectAlt = GeneralNames.getInstance(seq.getObjectAt(1));
      } else if (size == 1) {
        // error in the definition, so we have to guess
        ASN1Encodable obj = seq.getObjectAt(0);
        try {
          newSubject = X500Name.getInstance(obj);
        } catch (Exception e) {
          newSubjectAlt = GeneralNames.getInstance(obj);
        }
      } else {
        throw new HttpRespAuditException(HttpStatusCode.SC_BAD_REQUEST, "invalid ChangeSubjectName",
            AuditLevel.INFO, AuditStatus.FAILED);
      }

      if (newSubject != null) {
        requestedSubject = newSubject;
      }

      if (newSubjectAlt != null) {
        // replace the subjectAltNames extension
        List<Extension> v = new LinkedList<>();

        ASN1ObjectIdentifier sanOid = Extension.subjectAlternativeName;
        Extension sanExtn = null;

        // copy the extensions except SAN.
        if (csrExtns != null) {
          sanExtn = csrExtns.getExtension(sanOid);
          ASN1ObjectIdentifier[] csrExtnOids = csrExtns.getExtensionOIDs();
          for (ASN1ObjectIdentifier oid : csrExtnOids) {
            // ignore extension SAN
            if (!sanOid.equals(oid)) {
              v.add(csrExtns.getExtension(oid));
            }
          }
        }

        // set the extension SAN
        boolean critical = sanExtn != null && sanExtn.isCritical();
        v.add(new Extension(sanOid, critical, newSubjectAlt.getEncoded()));

        requestedExtns = new Extensions(v.toArray(new Extension[0]));
      }
    }

    template.setSubject(new X500NameType(requestedSubject));
    event.addEventData(CaAuditConstants.NAME_req_subject, "\"" + X509Util.x500NameText(requestedSubject) + "\"");

    try {
      template.extensions(requestedExtns);
    } catch (IOException e) {
      String message = "could not encode extensions";
      throw new HttpRespAuditException(HttpStatusCode.SC_BAD_REQUEST, message, AuditLevel.INFO, AuditStatus.FAILED);
    }

    EnrollCertsRequest.Entry[] templates = new EnrollCertsRequest.Entry[] {template};

    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setEntries(templates);
    sdkReq.setExplicitConfirm(false);
    sdkReq.setCaCertMode(CertsMode.NONE);

    EnrollOrPollCertsResponse sdkResp = sdk.reenrollCerts(caName, sdkReq);
    checkResponse(1, sdkResp);

    EnrollOrPollCertsResponse.Entry entry = getEntry(sdkResp.getEntries(), reqId);
    if (CMD_simplereenroll.equals(command)) {
      return HttpRespContent.ofOk(CT_pkcs7_mime_certyonly, true, buildCertsOnly(entry.getCert()));
    } else { // CMD_usimplereenroll
      return HttpRespContent.ofOk(CT_pkix_cert, true, entry.getCert());
    }
  } // method reenrollCert

  private HttpRespContent getCsrAttrs(String caName, String profile)
      throws IOException, SdkErrorResponseException {
    CertprofileInfoResponse sdkResp = sdk.profileInfo(caName, profile);
    ASN1EncodableVector csrAttrs = new ASN1EncodableVector();

    String[] extnTypes = sdkResp.getRequiredExtensionTypes();
    if (extnTypes != null && extnTypes.length != 0) {
      ASN1EncodableVector asn1ExtnTypes = new ASN1EncodableVector();
      for (String extnType : extnTypes) {
        asn1ExtnTypes.add(new ASN1ObjectIdentifier(extnType));
      }

      csrAttrs.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(asn1ExtnTypes)));
    }

    KeyType[] keyTypes = sdkResp.getKeyTypes();
    if (keyTypes != null) {
      for (KeyType keyType : keyTypes) {
        ASN1ObjectIdentifier typeOid = new ASN1ObjectIdentifier(keyType.getKeyType());
        String[] ecCurves = keyType.getEcCurves();
        if (ecCurves == null || ecCurves.length == 0) {
          csrAttrs.add(typeOid);
        } else {
          for (String ecCurve : ecCurves) {
            csrAttrs.add(new Attribute(typeOid, new DERSet(new ASN1ObjectIdentifier(ecCurve))));
          }
        }
      }
    }

    ASN1Sequence seq = new DERSequence(csrAttrs);
    return HttpRespContent.ofOk(CT_csrattrs, true, seq.getEncoded("DER"));
  }

  private static void checkResponse(int expectedSize, EnrollOrPollCertsResponse resp)
      throws HttpRespAuditException {
    EnrollOrPollCertsResponse.Entry[] entries = resp.getEntries();
    if (entries != null) {
      for (EnrollOrPollCertsResponse.Entry entry : entries) {
        if (entry.getError() != null) {
          throw new HttpRespAuditException(HttpStatusCode.SC_INTERNAL_SERVER_ERROR,
              entry.getError().toString(), AuditLevel.INFO, AuditStatus.FAILED);
        }
      }
    }

    int n = entries == null ? 0 : entries.length;
    if (n != expectedSize) {
      throw new HttpRespAuditException(HttpStatusCode.SC_INTERNAL_SERVER_ERROR,
          "expected " + expectedSize + " cert, but received " + n, AuditLevel.INFO, AuditStatus.FAILED);
    }
  }

  private static EnrollOrPollCertsResponse.Entry getEntry(
      EnrollOrPollCertsResponse.Entry[] entries, BigInteger certReqId)
      throws HttpRespAuditException {
    for (EnrollOrPollCertsResponse.Entry m : entries) {
      if (certReqId.equals(m.getId())) {
        return m;
      }
    }
    throw new HttpRespAuditException(HttpStatusCode.SC_INTERNAL_SERVER_ERROR,
        "found no response entry with certReqId " + certReqId, AuditLevel.INFO, AuditStatus.FAILED);
  }

  private static byte[] buildCertsOnly(byte[]... certsBytes) throws IOException {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (byte[] certBytes : certsBytes) {
      v.add(Certificate.getInstance(certBytes));
    }
    ASN1Set certs = new DERSet(v);

    SignedData sd = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null),
        certs, new DERSet(), new DERSet());

    ContentInfo ci = new ContentInfo(CMSObjectIdentifiers.signedData, sd);
    return ci.getEncoded("DER");
  }

  private static void writeLine(OutputStream os, String line) throws IOException {
    os.write(StringUtil.toUtf8Bytes(line));
    os.write(NEWLINE);
  }

}
