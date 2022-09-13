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

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.security.KeyCertBytesPair;
import org.xipki.util.exception.ErrorCode;
import org.xipki.util.http.HttpRespContent;
import org.xipki.util.http.XiHttpClient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.xipki.ca.sdk.SdkConstants.*;

/**
 * API client.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class SdkClient {

  private static final String CONTENT_TYPE_JSON = "application/json";

  private final String serverUrl;

  private final XiHttpClient client;

  public SdkClient(String serverUrl, SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
    this.serverUrl = serverUrl;
    this.client = new XiHttpClient(sslSocketFactory, hostnameVerifier);
  }

  private byte[] send(String ca, String command, SdkRequest request)
      throws IOException, SdkErrorResponseException {
    String ct = request == null ? null : CONTENT_TYPE_JSON;
    HttpRespContent resp;
    if (request == null) {
      resp = client.httpGet(serverUrl + ca + "/" + command);
    } else {
      resp = client.httpPost(serverUrl + ca + "/" + command, ct, request.encode(), CONTENT_TYPE_JSON);
    }

    if (resp.isOK()) {
      return resp.getContent();
    }

    byte[] errorContent = resp.getContent();
    if (errorContent == null) {
      throw new SdkErrorResponseException(ErrorCode.SYSTEM_FAILURE, null);
    } else {
      throw new SdkErrorResponseException(ErrorResponse.decode(errorContent));
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

  public byte[] cacert(String ca) throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_cacert, null);
    CertChainResponse resp = CertChainResponse.decode(respBytes);
    byte[][] certs = resp.getCertificates();
    return certs == null || certs.length == 0 ? null : certs[0];
  }

  public byte[][] cacerts(String ca) throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_cacert, null);
    CertChainResponse resp = CertChainResponse.decode(respBytes);
    return resp.getCertificates();
  }

  public CertprofileInfoResponse profileInfo(String ca, String profileName)
      throws IOException, SdkErrorResponseException {
    CertprofileInfoRequest req = new CertprofileInfoRequest();
    req.setProfile(profileName);
    byte[] respBytes = send(ca, CMD_profileinfo, req);
    return CertprofileInfoResponse.decode(respBytes);
  }

  public byte[] generateCrl(String ca, String crldp)
      throws IOException, SdkErrorResponseException {
    GenCRLRequest req = new GenCRLRequest();
    req.setCrlDp(crldp);
    byte[] respBytes = send(ca, CMD_gen_crl, req);
    CrlResponse resp = CrlResponse.decode(respBytes);
    return resp.getCrl();
  }

  public byte[] currentCrl(String ca) throws IOException, SdkErrorResponseException {
    return currentCrl(ca, null, null, null);
  }

  public byte[] currentCrl(String ca, BigInteger crlNumber, Date thisUpdate, String crlDp)
      throws IOException, SdkErrorResponseException {
    GetCRLRequest req = new GetCRLRequest();
    req.setCrlNumber(crlNumber);
    req.setCrlDp(crlDp);
    req.setThisUpdate(thisUpdate == null ? null : thisUpdate.getTime() / 1000);
    byte[] respBytes = send(ca, CMD_crl, req);
    CrlResponse resp = CrlResponse.decode(respBytes);
    return resp.getCrl();
  }

  private byte[] enrollCert0(String func, String cmd, String ca, EnrollCertRequestEntry reqEntry)
      throws IOException, SdkErrorResponseException {
    EnrollCertsRequest req = new EnrollCertsRequest();
    req.setCaCertMode(CertsMode.NONE);
    req.setEntries(Collections.singletonList(reqEntry));

    byte[] respBytes = send(ca, cmd, req);
    EnrollOrPollCertsResponse resp = EnrollOrPollCertsResponse.decode(respBytes);
    EnrollOrPullCertResponseEntry rEntry = resp.getEntries().get(0);
    byte[] cert = rEntry.getCert();
    if (cert == null) {
      throw new SdkErrorResponseException(ErrorCode.SYSTEM_FAILURE, "error " + func);
    }
    return cert;
  }

  private KeyCertBytesPair enrollCertCaGenKeypair0(String func, String cmd, String ca, EnrollCertRequestEntry reqEntry)
      throws IOException, SdkErrorResponseException {
    EnrollCertsRequest req = new EnrollCertsRequest();
    req.setCaCertMode(CertsMode.NONE);
    req.setEntries(Collections.singletonList(reqEntry));

    byte[] respBytes = send(ca, cmd, req);
    EnrollOrPollCertsResponse resp = EnrollOrPollCertsResponse.decode(respBytes);
    EnrollOrPullCertResponseEntry rEntry = resp.getEntries().get(0);
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

  public byte[] enrollKupCert(
      String ca, String certprofile, byte[] p10Req, X500Name oldCertIssuer, BigInteger oldCertSerialNumber)
      throws IOException, SdkErrorResponseException {
    EnrollCertRequestEntry reqEntry = new EnrollCertRequestEntry();
    reqEntry.setCertprofile(certprofile);
    reqEntry.setP10req(p10Req);
    OldCertInfoByIssuerAndSerial oldCertInfo = new OldCertInfoByIssuerAndSerial();
    oldCertInfo.setReusePublicKey(false);
    oldCertInfo.setSerialNumber(oldCertSerialNumber);
    oldCertInfo.setIssuer(new X500NameType(oldCertIssuer));
    reqEntry.setOldCertIsn(oldCertInfo);
    return enrollCert0("enrollKupCert", CMD_enroll_kup, ca, reqEntry);
  }

  public KeyCertBytesPair enrollKupCertCaGenKeypair(
      String ca, String certprofile, X500Name subject, String oldCertIssuer, BigInteger oldCertSerialNumber)
      throws IOException, SdkErrorResponseException {
    EnrollCertRequestEntry reqEntry = new EnrollCertRequestEntry();
    reqEntry.setCertprofile(certprofile);
    reqEntry.setSubject(new X500NameType(subject));
    OldCertInfoByIssuerAndSerial oldCertInfo = new OldCertInfoByIssuerAndSerial();
    oldCertInfo.setReusePublicKey(false);
    oldCertInfo.setSerialNumber(oldCertSerialNumber);
    oldCertInfo.setIssuer(new X500NameType(oldCertIssuer));
    reqEntry.setOldCertIsn(oldCertInfo);
    return enrollCertCaGenKeypair0("enrollKupCertCaGenKeypair", CMD_enroll_kup, ca, reqEntry);
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

  public EnrollOrPollCertsResponse enrollKupCerts(String ca, EnrollCertsRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_enroll_kup, req);
    return checkEnrollResp(respBytes, req);
  }

  private EnrollOrPollCertsResponse checkEnrollResp(byte[] respBytes, EnrollCertsRequest req)
      throws IOException {
    EnrollOrPollCertsResponse resp = EnrollOrPollCertsResponse.decode(respBytes);
    List<EnrollOrPullCertResponseEntry> entries = resp.getEntries();
    int expectedSize = req.getEntries().size();
    int size = entries == null ? 0 : entries.size();
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
    TransactionIdRequest req = new TransactionIdRequest();
    req.setTid(tid);
    send(ca, CMD_revoke_pending_cert, req);
  }

  public EnrollOrPollCertsResponse pollCerts(String ca, PollCertRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_poll_cert, req);
    return EnrollOrPollCertsResponse.decode(respBytes);
  }

  public RevokeCertsResponse revokeCerts(String ca, RevokeCertsRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_revoke_cert, req);
    return RevokeCertsResponse.decode(respBytes);
  }

  public UnSuspendOrRemoveCertsResponse unsuspendCerts(String ca, UnsuspendOrRemoveRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_unsuspend_cert, req);
    return UnSuspendOrRemoveCertsResponse.decode(respBytes);
  }

  public UnSuspendOrRemoveCertsResponse removeCerts(String ca, UnsuspendOrRemoveRequest req)
      throws IOException, SdkErrorResponseException {
    byte[] respBytes = send(ca, CMD_remove_cert, req);
    return UnSuspendOrRemoveCertsResponse.decode(respBytes);
  }

  public byte[] getCert(String caName, X500Name issuer, BigInteger serialNumber)
      throws IOException, SdkErrorResponseException {
    GetCertRequest req = new GetCertRequest();
    req.setIssuer(new X500NameType(issuer));
    req.setSerialNumber(serialNumber);
    byte[] respBytes = send(caName, CMD_get_cert, req);
    PayloadResponse resp = PayloadResponse.decode(respBytes);
    return resp.getPayload();
  }

}
