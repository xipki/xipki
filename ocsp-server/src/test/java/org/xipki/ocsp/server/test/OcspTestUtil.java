// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.test;

import org.junit.Assert;
import org.xipki.asn1.ocsp.BasicOCSPResponse;
import org.xipki.asn1.ocsp.CertID;
import org.xipki.asn1.ocsp.OCSPRequest;
import org.xipki.asn1.ocsp.OCSPResponse;
import org.xipki.asn1.ocsp.OCSPResponseStatus;
import org.xipki.asn1.ocsp.OcspCertStatus;
import org.xipki.asn1.ocsp.Request;
import org.xipki.asn1.ocsp.SingleResponse;
import org.xipki.asn1.ocsp.TBSRequest;
import org.xipki.asn1.x509.CRLReason;
import org.xipki.codec.Base64;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.util.KeyUtil;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Helpers of the OCSP server tests: configuration of a responder with one store, requests and
 * the status in the responses.
 *
 * @author Lijun Liao (xipki)
 */
public final class OcspTestUtil {

  private OcspTestUtil() {
  }

  /** The status of the certificate in the response of the responder. */
  static OcspCertStatus status(OcspServer server, Responder responder, X509Cert issuer,
                               BigInteger serial) throws Exception {
    OCSPResponse resp = OCSPResponse.fromEncoded(
        server.answer(responder, request(certId(issuer, serial)), false).response());
    Assert.assertEquals(OCSPResponseStatus.SUCCESSFUL, resp.getResponseStatus());
    BasicOCSPResponse basic = resp.getBasicOCSPResponse();
    List<SingleResponse> responses = new ArrayList<>();
    for (Object entry : basic.getResponses()) {
      responses.add((SingleResponse) entry);
    }
    Assert.assertEquals(1, responses.size());
    return responses.get(0).getCertStatus();
  }

  /** RFC 6960, section 2.2: non-issued certificates are revoked, certificateHold, time 0. */
  static void assertNonIssued(OcspCertStatus status) {
    Assert.assertNotNull("revoked", status.getRevoked());
    Assert.assertEquals(CRLReason.certificateHold, status.getRevoked().getRevocationReason());
    Assert.assertEquals(Instant.EPOCH, status.getRevoked().getRevocationTime().getTime());
  }

  public static byte[] request(CertID certId) throws Exception {
    TBSRequest tbs = new TBSRequest(null,
        new Request.Seq0(List.of(new Request(certId, null))), null);
    return new OCSPRequest(tbs, null).getEncoded();
  }

  public static CertID certId(X509Cert issuer, BigInteger serial) {
    HashAlgo hashAlgo = HashAlgo.SHA1;
    Asn1OctetString nameHash = new Asn1OctetString(hashAlgo.hash(issuer.subject().getEncoded()));
    Asn1OctetString keyHash = new Asn1OctetString(hashAlgo.hash(
        issuer.getCert().getTBSCertificate().getSubjectPublicKeyInfo().subjectPublicKey()));
    return new CertID(hashAlgo.algorithmIdentifier(), nameHash, keyHash,
        new Asn1Integer(serial));
  }

  /**
   * Writes the configuration of the OCSP server with the responder {@code responder1} and one
   * store.
   *
   * @param dir the directory of the file.
   * @param dbConf the configuration file of the database of the store.
   * @param source the JSON of the source of the store, e.g.
   *        {@code {"datasource": "ocspdb", "type": "xipki-db", "conf": {}}}.
   * @param unknownCertBehaviour the status of certificates unknown to the store
   *        ({@code unknown}, {@code good}, ...).
   * @param extra additional members of the top-level JSON object, with leading comma, or "".
   */
  public static Path writeResponderConf(Path dir, Path dbConf, String source,
                                 String unknownCertBehaviour, String extra) throws Exception {
    byte[] signerKeystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters("CHANGEIT".toCharArray())).keystore();
    return writeResponderConf(dir, dbConf, source, unknownCertBehaviour, extra,
        "\"type\": \"pkcs12\",\n"
        + "    \"key\": \"password=CHANGEIT,keystore=base64:"
        + Base64.encodeToString(signerKeystore) + "\"");
  }

  /**
   * As {@link #writeResponderConf(Path, Path, String, String, String)}, with the given members of
   * the signer {@code signer1}, e.g.
   * {@code "type": "pkcs11", "key": "module=default,slot=0,key-label=k1", "cert": {...}}.
   */
  public static Path writeResponderConf(Path dir, Path dbConf, String source,
                                        String unknownCertBehaviour, String extra,
                                        String signerMembers) throws Exception {
    String dbConfPath = dbConf.toAbsolutePath().toString().replace("\\", "/");
    String conf = "{\n"
        + "  \"master\": true,\n"
        + "  \"unknownIssuerBehaviour\": \"malformedRequest\",\n"
        + "  \"datasources\": [{\"name\": \"ocspdb\","
        + " \"conf\": {\"file\": \"" + dbConfPath + "\"}}],\n"
        + "  \"requestOptions\": [{\n"
        + "    \"name\": \"request1\",\n"
        + "    \"hashAlgorithms\": [\"SHA1\", \"SHA256\"],\n"
        + "    \"maxRequestListCount\": 10,\n"
        + "    \"maxRequestSize\": 4096,\n"
        + "    \"nonce\": {\"maxLen\": 32, \"minLen\": 4, \"occurrence\": \"optional\"},\n"
        + "    \"signatureRequired\": false,\n"
        + "    \"supportsHttpGet\": true,\n"
        + "    \"validateSignature\": false,\n"
        + "    \"versions\": [\"v1\"]\n"
        + "  }],\n"
        + "  \"responders\": [{\n"
        + "    \"name\": \"responder1\",\n"
        + "    \"inheritCaRevocation\": true,\n"
        + "    \"mode\": \"RFC6960\",\n"
        + "    \"request\": \"request1\",\n"
        + "    \"response\": \"response1\",\n"
        + "    \"servletPaths\": [\"/\"],\n"
        + "    \"signer\": \"signer1\",\n"
        + "    \"stores\": [\"store1\"]\n"
        + "  }],\n"
        + "  \"responseOptions\": [{\n"
        + "    \"name\": \"response1\",\n"
        + "    \"embedCertsMode\": \"CERT\",\n"
        + "    \"includeCerthash\": false,\n"
        + "    \"includeInvalidityDate\": false,\n"
        + "    \"includeRevReason\": true,\n"
        + "    \"responderIdByName\": true\n"
        + "  }],\n"
        + "  \"signers\": [{\n"
        + "    \"name\": \"signer1\",\n"
        + "    " + signerMembers + "\n"
        + "  }],\n"
        + "  \"stores\": [{\n"
        + "    \"name\": \"store1\",\n"
        + "    \"ignoreExpiredCert\": true,\n"
        + "    \"ignoreNotYetValidCert\": true,\n"
        + "    \"includeArchiveCutoff\": false,\n"
        + "    \"includeCrlId\": false,\n"
        + "    \"retentionInterval\": -1,\n"
        + "    \"minNextUpdatePeriod\": \"1d\",\n"
        + "    \"unknownCertBehaviour\": \"" + unknownCertBehaviour + "\",\n"
        + "    \"updateInterval\": \"10m\",\n"
        + "    \"source\": " + source + "\n"
        + "  }]" + extra + "\n"
        + "}\n";
    Path file = Files.createTempFile(dir, "ocsp-responder", ".json");
    Files.writeString(file, conf);
    return file;
  }

}
