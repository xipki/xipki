// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.security.KeyCertBytesPair;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.EncodeException;
import org.xipki.util.exception.ErrorCode;
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

import static org.xipki.ca.sdk.SdkConstants.*;

/**
 * API client.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class SdkClient {

  private static final String CONTENT_TYPE_CBOR = "application/cbor";

  private final String serverUrl;

  private final XiHttpClient client;

  public SdkClient(SdkClientConf conf) throws ObjectCreationException {
    this.serverUrl = conf.getServerUrl();
    SslContextConf sdkSslConf = SslContextConf.ofSslConf(conf.getSsl());
    this.client = new XiHttpClient(sdkSslConf.getSslSocketFactory(), sdkSslConf.buildHostnameVerifier());
  }

  public SdkClient(String serverUrl, SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
    this.serverUrl = serverUrl;
    this.client = new XiHttpClient(sslSocketFactory, hostnameVerifier);
  }

  public byte[] send(String ca, String command, SdkRequest request)
      throws IOException, SdkErrorResponseException {
    String ct = request == null ? null : CONTENT_TYPE_CBOR;
    HttpRespContent resp;

    String prefix = ca == null ? serverUrl + "-/" : serverUrl + ca + "/";

    if (request == null) {
      resp = client.httpGet(prefix + command);
    } else {
      byte[] encodedReq;
      try {
        encodedReq = request.encode();
      } catch (EncodeException e) {
        throw new SdkErrorResponseException(ErrorCode.CLIENT_REQUEST_ENCODE_ERROR, e.getMessage());
      }

      resp = client.httpPost(prefix + command, ct, encodedReq, CONTENT_TYPE_CBOR);
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

  public byte[] cacert(String ca)
      throws IOException, SdkErrorResponseException {
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

  public byte[][] cacerts(String ca)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_cacerts, null);
    CertChainResponse resp;
    try {
      resp = CertChainResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    return resp.getCertificates();
  }

  public byte[] cacertBySubject(byte[] subject)
      throws IOException, SdkErrorResponseException {
    X500NameType issuer = new X500NameType(subject);
    CaIdentifierRequest req = new CaIdentifierRequest();
    req.setIssuer(issuer);

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

  public byte[][] cacertsBySubject(byte[] subject)
      throws IOException, SdkErrorResponseException {
    X500NameType issuer = new X500NameType(subject);
    CaIdentifierRequest req = new CaIdentifierRequest();
    req.setIssuer(issuer);
    byte[] respBytes = send(null, CMD_cacerts2, req);
    CertChainResponse resp;
    try {
      resp = CertChainResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    return resp.getCertificates();
  }

  public CaNameResponse caNameBySubject(byte[] subject)
      throws IOException, SdkErrorResponseException {
    X500NameType issuer = new X500NameType(subject);
    CaIdentifierRequest req = new CaIdentifierRequest();
    req.setIssuer(issuer);
    byte[] respBytes = send(null, CMD_caname, req);
    try {
      return CaNameResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public CertprofileInfoResponse profileInfo(String ca, String profileName)
      throws IOException, SdkErrorResponseException {
    CertprofileInfoRequest req = new CertprofileInfoRequest(profileName);
    byte[] respBytes = send(ca, CMD_profileinfo, req);
    try {
      return CertprofileInfoResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public byte[] generateCrl(String ca, String crldp)
      throws IOException, SdkErrorResponseException {
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

  public byte[] currentCrl(String ca)
      throws IOException, SdkErrorResponseException {
    return currentCrl(ca, null, null, null);
  }

  public byte[] currentCrl(String ca, BigInteger crlNumber, Instant thisUpdate, String crlDp)
      throws IOException, SdkErrorResponseException {
    GetCRLRequest req = new GetCRLRequest(crlNumber, thisUpdate == null ? null : thisUpdate.getEpochSecond(), crlDp);
    byte[] respBytes = send(ca, CMD_crl, req);
    CrlResponse resp;
    try {
      resp = CrlResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
    return resp.getCrl();
  }

  private byte[] enrollCert0(String func, String cmd, String ca, EnrollCertRequestEntry reqEntry)
      throws IOException, SdkErrorResponseException {
    EnrollCertsRequest req = new EnrollCertsRequest();
    req.setCaCertMode(CertsMode.NONE);
    req.setEntries(new EnrollCertRequestEntry[]{reqEntry});

    byte[] respBytes = send(ca, cmd, req);
    EnrollOrPollCertsResponse resp;
    try {
      resp = EnrollOrPollCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }

    EnrollOrPullCertResponseEntry rEntry = resp.getEntries()[0];
    return Optional.ofNullable(rEntry.getCert()).orElseThrow(() ->
        new SdkErrorResponseException(ErrorCode.SYSTEM_FAILURE, "error " + func));
  }

  private KeyCertBytesPair enrollCertCaGenKeypair0(String func, String cmd, String ca, EnrollCertRequestEntry reqEntry)
      throws IOException, SdkErrorResponseException {
    EnrollCertsRequest req = new EnrollCertsRequest();
    req.setCaCertMode(CertsMode.NONE);
    req.setEntries(new EnrollCertRequestEntry[]{reqEntry});

    byte[] respBytes = send(ca, cmd, req);
    EnrollOrPollCertsResponse resp;
    try {
      resp = EnrollOrPollCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }

    EnrollOrPullCertResponseEntry rEntry = resp.getEntries()[0];
    if (rEntry.getCert() == null || rEntry.getPrivateKey() == null) {
      throw new SdkErrorResponseException(ErrorCode.SYSTEM_FAILURE, "error " + func);
    }
    return new KeyCertBytesPair(rEntry.getPrivateKey(), rEntry.getCert());
  }

  public byte[] enrollCert(String ca, String certprofile, byte[] p10Req)
      throws IOException, SdkErrorResponseException {
    EnrollCertRequestEntry reqEntry = new EnrollCertRequestEntry();
    reqEntry.setP10req(p10Req);
    reqEntry.setCertprofile(certprofile);
    return enrollCert0("enrollCert", CMD_enroll, ca, reqEntry);
  }

  public KeyCertBytesPair enrollCertCaGenKeypair(String ca, String certprofile, String subject)
      throws IOException, SdkErrorResponseException {
    EnrollCertRequestEntry reqEntry = new EnrollCertRequestEntry();
    reqEntry.setSubject(new X500NameType(subject));
    reqEntry.setCertprofile(certprofile);
    return enrollCertCaGenKeypair0("enrollCertCaGenKeypair", CMD_enroll, ca, reqEntry);
  }

  public byte[] reenrollCert(
      String ca, String certprofile, byte[] p10Req, X500Name oldCertIssuer, BigInteger oldCertSerialNumber)
      throws IOException, SdkErrorResponseException {
    EnrollCertRequestEntry reqEntry = new EnrollCertRequestEntry();
    reqEntry.setCertprofile(certprofile);
    reqEntry.setP10req(p10Req);
    reqEntry.setOldCertIsn(new OldCertInfoByIssuerAndSerial(
        false, new X500NameType(oldCertIssuer), oldCertSerialNumber));
    return enrollCert0("reenrollCert", CMD_reenroll, ca, reqEntry);
  }

  public KeyCertBytesPair reenrollCertCaGenKeypair(
      String ca, String certprofile, X500Name subject, String oldCertIssuer, BigInteger oldCertSerialNumber)
      throws IOException, SdkErrorResponseException {
    EnrollCertRequestEntry reqEntry = new EnrollCertRequestEntry();
    reqEntry.setCertprofile(certprofile);
    reqEntry.setSubject(new X500NameType(subject));
    reqEntry.setOldCertIsn(
        new OldCertInfoByIssuerAndSerial(false, new X500NameType(oldCertIssuer), oldCertSerialNumber));
    return enrollCertCaGenKeypair0("reenrollCertCaGenKeypair", CMD_reenroll, ca, reqEntry);
  }

  public EnrollOrPollCertsResponse enrollCerts(String ca, EnrollCertsRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_enroll, req);
    return checkEnrollResp(respBytes, req);
  }

  public EnrollOrPollCertsResponse enrollCrossCerts(String ca, EnrollCertsRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_enroll_cross, req);
    return checkEnrollResp(respBytes, req);
  }

  public EnrollOrPollCertsResponse reenrollCerts(String ca, EnrollCertsRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_reenroll, req);
    return checkEnrollResp(respBytes, req);
  }

  private EnrollOrPollCertsResponse checkEnrollResp(byte[] respBytes, EnrollCertsRequest req)
      throws IOException, SdkErrorResponseException {
    EnrollOrPollCertsResponse resp;
    try {
      resp = EnrollOrPollCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }

    EnrollOrPullCertResponseEntry[] entries = resp.getEntries();
    int expectedSize = req.getEntries().length;
    int size = entries == null ? 0 : entries.length;
    if (expectedSize != size) {
      throw new IOException("expected " + expectedSize + " entries, but received " + size);
    }
    return resp;
  }

  public void confirmCerts(String ca, ConfirmCertsRequest req)
      throws IOException, SdkErrorResponseException {
    send(ca, CMD_confirm_enroll, req);
  }

  public void revokePendingCerts(String ca, String tid)
      throws IOException, SdkErrorResponseException {
    TransactionIdRequest req = new TransactionIdRequest(tid);
    send(ca, CMD_revoke_pending_cert, req);
  }

  public EnrollOrPollCertsResponse pollCerts(PollCertRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(null, CMD_poll_cert, req);
    try {
      return EnrollOrPollCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public RevokeCertsResponse revokeCerts(RevokeCertsRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(null, CMD_revoke_cert, req);
    try {
      return RevokeCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public UnSuspendOrRemoveCertsResponse unsuspendCerts(UnsuspendOrRemoveRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(null, CMD_unsuspend_cert, req);
    try {
      return UnSuspendOrRemoveCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public UnSuspendOrRemoveCertsResponse removeCerts(UnsuspendOrRemoveRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(null, CMD_remove_cert, req);
    try {
      return UnSuspendOrRemoveCertsResponse.decode(respBytes);
    } catch (DecodeException e) {
      throw new SdkErrorResponseException(ErrorCode.CLIENT_RESPONSE_DECODE_ERROR, e.getMessage());
    }
  }

  public byte[] getCert(String caName, X500Name issuer, BigInteger serialNumber)
      throws IOException, SdkErrorResponseException {
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
