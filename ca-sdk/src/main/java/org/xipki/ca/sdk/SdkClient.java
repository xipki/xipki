// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pki.ErrorCode;
import org.xipki.security.KeyCertBytesPair;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.HttpRespContent;
import org.xipki.util.http.SslContextConf;
import org.xipki.util.http.XiHttpClient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Optional;

import static org.xipki.ca.sdk.SdkConstants.CMD_cacert;
import static org.xipki.ca.sdk.SdkConstants.CMD_cacert2;
import static org.xipki.ca.sdk.SdkConstants.CMD_cacerts;
import static org.xipki.ca.sdk.SdkConstants.CMD_cacerts2;
import static org.xipki.ca.sdk.SdkConstants.CMD_caname;
import static org.xipki.ca.sdk.SdkConstants.CMD_confirm_enroll;
import static org.xipki.ca.sdk.SdkConstants.CMD_crl;
import static org.xipki.ca.sdk.SdkConstants.CMD_enroll;
import static org.xipki.ca.sdk.SdkConstants.CMD_enroll_cross;
import static org.xipki.ca.sdk.SdkConstants.CMD_gen_crl;
import static org.xipki.ca.sdk.SdkConstants.CMD_get_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_health;
import static org.xipki.ca.sdk.SdkConstants.CMD_poll_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_profileinfo;
import static org.xipki.ca.sdk.SdkConstants.CMD_reenroll;
import static org.xipki.ca.sdk.SdkConstants.CMD_remove_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_revoke_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_revoke_pending_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_unsuspend_cert;

/**
 * API client.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class SdkClient {

  private static final Logger LOG = LoggerFactory.getLogger(SdkClient.class);

  private static final String CONTENT_TYPE_CBOR = "application/cbor";

  private final String serverUrl;

  private final XiHttpClient client;

  public SdkClient(SdkClientConf conf) throws ObjectCreationException {
    this.serverUrl = conf.getServerUrl();
    SslContextConf sdkSslConf = SslContextConf.ofSslConf(conf.getSsl());
    this.client = new XiHttpClient(sdkSslConf.getSslSocketFactory(), sdkSslConf.getHostnameVerifier());
  }

  public SdkClient(String serverUrl, SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
    this.serverUrl = serverUrl;
    this.client = new XiHttpClient(sslSocketFactory, hostnameVerifier);
  }

  public byte[] send(String ca, String command, SdkRequest request)
      throws SdkErrorResponseException {
    String ct = request == null ? null : CONTENT_TYPE_CBOR;
    HttpRespContent resp;

    String prefix = ca == null ? serverUrl + "-/" : serverUrl + ca + "/";

    try {
      if (request == null) {
        resp = client.httpGet(prefix + command);
      } else {
        byte[] encodedReq;
        try {
          encodedReq = request.encode();
        } catch (EncodeException e) {
          LogUtil.warn(LOG, e, e.getMessage());
          throw new SdkErrorResponseException(ErrorCode.CLIENT_REQUEST_ENCODE_ERROR, e.getMessage());
        }

        resp = client.httpPost(prefix + command, ct, encodedReq, CONTENT_TYPE_CBOR);
      }
    } catch (IOException ex) {
      throw new SdkErrorResponseException(ErrorCode.SYSTEM_UNAVAILABLE, "IO error sending request to the CA");
    }

    if (resp.isOK()) {
      return resp.getContent();
    }

    byte[] errorContent = resp.getContent();
    if (errorContent == null) {
      throw new SdkErrorResponseException(ErrorCode.SYSTEM_FAILURE, null);
    } else {
      try {
        throw new SdkErrorResponseException(ErrorResponse.decode(errorContent));
      } catch (DecodeException e) {
        throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
      }
    }
  } // method send

  public boolean healthy(String ca) {
    try {
      send(ca, CMD_health, null);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  public byte[] cacert(String ca) throws SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_cacert, null);
    CertChainResponse resp;
    try {
      resp = CertChainResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    byte[][] certs = resp.getCertificates();
    return certs == null || certs.length == 0 ? null : certs[0];
  }

  public byte[][] cacerts(String ca) throws SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_cacerts, null);
    CertChainResponse resp;
    try {
      resp = CertChainResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    return resp.getCertificates();
  }

  public byte[] cacertBySubject(byte[] subject) throws SdkErrorResponseException {
    X500NameType issuer = new X500NameType(subject);
    CaIdentifierRequest req = new CaIdentifierRequest(null, issuer, null);

    byte[] respBytes = send(null, CMD_cacert2, req);
    CertChainResponse resp;
    try {
      resp = CertChainResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    byte[][] certs = resp.getCertificates();
    return certs == null || certs.length == 0 ? null : certs[0];
  }

  public byte[][] cacertsBySubject(byte[] subject) throws SdkErrorResponseException {
    X500NameType issuer = new X500NameType(subject);
    CaIdentifierRequest req = new CaIdentifierRequest(null, issuer, null);
    byte[] respBytes = send(null, CMD_cacerts2, req);
    CertChainResponse resp;
    try {
      resp = CertChainResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    return resp.getCertificates();
  }

  public CaNameResponse caNameBySubject(byte[] subject) throws SdkErrorResponseException {
    X500NameType issuer = new X500NameType(subject);
    CaIdentifierRequest req = new CaIdentifierRequest(null, issuer, null);
    byte[] respBytes = send(null, CMD_caname, req);
    try {
      return CaNameResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public CertprofileInfoResponse profileInfo(String ca, String profileName) throws SdkErrorResponseException {
    CertprofileInfoRequest req = new CertprofileInfoRequest(profileName);
    byte[] respBytes = send(ca, CMD_profileinfo, req);
    try {
      return CertprofileInfoResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public byte[] generateCrl(String ca, String crldp) throws SdkErrorResponseException {
    GenCRLRequest req = new GenCRLRequest(crldp);
    byte[] respBytes = send(ca, CMD_gen_crl, req);
    CrlResponse resp;
    try {
      resp = CrlResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }

    return resp.getCrl();
  }

  public byte[] currentCrl(String ca) throws SdkErrorResponseException {
    return currentCrl(ca, null, null, null);
  }

  public byte[] currentCrl(String ca, BigInteger crlNumber, Instant thisUpdate, String crlDp)
      throws SdkErrorResponseException {
    GetCRLRequest req = new GetCRLRequest(crlNumber, thisUpdate, crlDp);
    byte[] respBytes = send(ca, CMD_crl, req);
    CrlResponse resp;
    try {
      resp = CrlResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    return resp.getCrl();
  }

  private byte[] enrollCert0(String func, String cmd, String ca, EnrollCertsRequest.Entry reqEntry)
      throws SdkErrorResponseException {
    EnrollCertsRequest req = new EnrollCertsRequest();
    req.setCaCertMode(CertsMode.NONE);
    req.setEntries(new EnrollCertsRequest.Entry[]{reqEntry});

    byte[] respBytes = send(ca, cmd, req);
    EnrollOrPollCertsResponse resp;
    try {
      resp = EnrollOrPollCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }

    EnrollOrPollCertsResponse.Entry rEntry = resp.getEntries()[0];
    return Optional.ofNullable(rEntry.getCert()).orElseThrow(() ->
        new SdkErrorResponseException(ErrorCode.SYSTEM_FAILURE, "error " + func));
  }

  private KeyCertBytesPair enrollCertCaGenKeypair0(
      String func, String cmd, String ca, EnrollCertsRequest.Entry reqEntry)
      throws SdkErrorResponseException {
    EnrollCertsRequest req = new EnrollCertsRequest();
    req.setCaCertMode(CertsMode.NONE);
    req.setEntries(new EnrollCertsRequest.Entry[]{reqEntry});

    byte[] respBytes = send(ca, cmd, req);
    EnrollOrPollCertsResponse resp;
    try {
      resp = EnrollOrPollCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }

    EnrollOrPollCertsResponse.Entry rEntry = resp.getEntries()[0];
    if (rEntry.getCert() == null || rEntry.getPrivateKey() == null) {
      throw new SdkErrorResponseException(ErrorCode.SYSTEM_FAILURE, "error " + func);
    }
    return new KeyCertBytesPair(rEntry.getPrivateKey(), rEntry.getCert());
  }

  public byte[] enrollCert(String ca, String certprofile, byte[] p10Req)
      throws SdkErrorResponseException {
    EnrollCertsRequest.Entry reqEntry = new EnrollCertsRequest.Entry();
    reqEntry.setP10req(p10Req);
    reqEntry.setCertprofile(certprofile);
    return enrollCert0("enrollCert", CMD_enroll, ca, reqEntry);
  }

  public KeyCertBytesPair enrollCertCaGenKeypair(String ca, String certprofile, String subject)
      throws SdkErrorResponseException {
    EnrollCertsRequest.Entry reqEntry = new EnrollCertsRequest.Entry();
    reqEntry.setSubject(new X500NameType(subject));
    reqEntry.setCertprofile(certprofile);
    return enrollCertCaGenKeypair0("enrollCertCaGenKeypair", CMD_enroll, ca, reqEntry);
  }

  public byte[] reenrollCert(
      String ca, String certprofile, byte[] p10Req, X500Name oldCertIssuer, BigInteger oldCertSerialNumber)
      throws SdkErrorResponseException {
    EnrollCertsRequest.Entry reqEntry = new EnrollCertsRequest.Entry();
    reqEntry.setCertprofile(certprofile);
    reqEntry.setP10req(p10Req);
    OldCertInfo oldCertInfo = new OldCertInfo(false, new OldCertInfo.ByIssuerAndSerial(
        new X500NameType(oldCertIssuer), oldCertSerialNumber));
    reqEntry.setOldCertInfo(oldCertInfo);
    return enrollCert0("reenrollCert", CMD_reenroll, ca, reqEntry);
  }

  public KeyCertBytesPair reenrollCertCaGenKeypair(
      String ca, String certprofile, X500Name subject, String oldCertIssuer, BigInteger oldCertSerialNumber)
      throws SdkErrorResponseException {
    EnrollCertsRequest.Entry reqEntry = new EnrollCertsRequest.Entry();
    reqEntry.setCertprofile(certprofile);
    reqEntry.setSubject(new X500NameType(subject));
    OldCertInfo oldCertInfo = new OldCertInfo(false, new OldCertInfo.ByIssuerAndSerial(
        new X500NameType(oldCertIssuer), oldCertSerialNumber));
    reqEntry.setOldCertInfo(oldCertInfo);
    return enrollCertCaGenKeypair0("reenrollCertCaGenKeypair", CMD_reenroll, ca, reqEntry);
  }

  public EnrollOrPollCertsResponse enrollCerts(String ca, EnrollCertsRequest req) throws SdkErrorResponseException {
    checkEnrollCertsRequest(req);
    byte[] respBytes = send(ca, CMD_enroll, req);
    return checkEnrollResp(respBytes, req);
  }

  public EnrollOrPollCertsResponse enrollCrossCerts(String ca, EnrollCertsRequest req)
      throws SdkErrorResponseException {
    checkEnrollCertsRequest(req);
    byte[] respBytes = send(ca, CMD_enroll_cross, req);
    return checkEnrollResp(respBytes, req);
  }

  private static void checkEnrollCertsRequest(EnrollCertsRequest req) throws SdkErrorResponseException {
    for (EnrollCertsRequest.Entry m : req.getEntries()) {
      String profile = m.getCertprofile();
      if (StringUtil.isBlank(profile)) {
        throw new SdkErrorResponseException(ErrorCode.UNKNOWN_CERT_PROFILE, "cert profile not set");
      }
    }
  }

  public EnrollOrPollCertsResponse reenrollCerts(String ca, EnrollCertsRequest req) throws SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_reenroll, req);
    return checkEnrollResp(respBytes, req);
  }

  private EnrollOrPollCertsResponse checkEnrollResp(byte[] respBytes, EnrollCertsRequest req)
      throws SdkErrorResponseException {
    EnrollOrPollCertsResponse resp;
    try {
      resp = EnrollOrPollCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }

    EnrollOrPollCertsResponse.Entry[] entries = resp.getEntries();
    int expectedSize = req.getEntries().length;
    int size = entries == null ? 0 : entries.length;
    if (expectedSize != size) {
      throw new SdkErrorResponseException(ErrorCode.SYSTEM_FAILURE,
          "expected " + expectedSize + " entries, but received " + size);
    }
    return resp;
  }

  public void confirmCerts(String ca, ConfirmCertsRequest req) throws SdkErrorResponseException {
    send(ca, CMD_confirm_enroll, req);
  }

  public void revokePendingCerts(String ca, String tid) throws SdkErrorResponseException {
    TransactionIdRequest req = new TransactionIdRequest(tid);
    send(ca, CMD_revoke_pending_cert, req);
  }

  public EnrollOrPollCertsResponse pollCerts(PollCertRequest req) throws SdkErrorResponseException {
    byte[] respBytes = send(null, CMD_poll_cert, req);
    try {
      return EnrollOrPollCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public RevokeCertsResponse revokeCerts(RevokeCertsRequest req) throws SdkErrorResponseException {
    byte[] respBytes = send(null, CMD_revoke_cert, req);
    try {
      return RevokeCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public UnSuspendOrRemoveCertsResponse unsuspendCerts(UnsuspendOrRemoveCertsRequest req)
      throws SdkErrorResponseException {
    byte[] respBytes = send(null, CMD_unsuspend_cert, req);
    try {
      return UnSuspendOrRemoveCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public UnSuspendOrRemoveCertsResponse removeCerts(UnsuspendOrRemoveCertsRequest req)
      throws SdkErrorResponseException {
    byte[] respBytes = send(null, CMD_remove_cert, req);
    try {
      return UnSuspendOrRemoveCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public byte[] getCert(String caName, X500Name issuer, BigInteger serialNumber)
      throws SdkErrorResponseException {
    GetCertRequest req = new GetCertRequest(serialNumber, new X500NameType(issuer));
    byte[] respBytes = send(caName, CMD_get_cert, req);
    PayloadResponse resp;
    try {
      resp = PayloadResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    return resp.getPayload();
  }

}
