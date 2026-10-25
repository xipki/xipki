// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.pkix.asn1.ocsp.BasicOCSPResponse;
import org.xipki.pkix.asn1.ocsp.CertID;
import org.xipki.pkix.asn1.ocsp.OCSPRequest;
import org.xipki.pkix.asn1.ocsp.OCSPResponse;
import org.xipki.pkix.asn1.ocsp.OCSPResponseStatus;
import org.xipki.pkix.asn1.ocsp.PreferredSignatureAlgorithm;
import org.xipki.pkix.asn1.ocsp.PreferredSignatureAlgorithms;
import org.xipki.pkix.asn1.ocsp.Request;
import org.xipki.pkix.asn1.ocsp.SingleResponse;
import org.xipki.codec.asn1.oid.OcspOIDs;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.pkix.asn1.x509.TBSCertificate;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.pkix.exception.OCSPException;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.exception.NoIdleSignerException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.http.Curl;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.util.http.ReqRespDebug;
import org.xipki.util.http.ReqRespDebug.ReqRespPair;
import org.xipki.pkix.util.conf.FileOrBinary;
import org.xipki.codec.util.IoUtil;
import org.xipki.pkix.util.io.XipkiIoUtil;
import org.xipki.pkix.util.misc.StringUtil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * HTTP OCSP Requestor.
 *
 * @author Lijun Liao (xipki)
 */
public class HttpOcspRequestor implements OcspRequestor {

  private static final Logger LOG = LoggerFactory.getLogger(HttpOcspRequestor.class);

  // result in maximal 254 Base-64 encoded octets
  private static final int MAX_LEN_GET = 190;

  private static final String CT_REQUEST = "application/ocsp-request";

  private static final String CT_RESPONSE = "application/ocsp-response";

  private SecurityFactory securityFactory;

  private ConcurrentSigner signer;

  private String confFile = "xipki/etc/ocsp-client.json";

  private final SecureRandom random = new SecureRandom();

  private final AtomicBoolean initFinished = new AtomicBoolean(false);

  private final AtomicBoolean initSucc = new AtomicBoolean(false);

  public HttpOcspRequestor() {
  }

  /**
   * Sends the request to the OCSP responder.
   * @param request
   *          Request. Must not be {@code null}.
   * @param responderUrl
   *          Responder URL. Must not be {@code null}.
   * @param requestOptions
   *           Request options. Must not be {@code null}.
   * @return received response
   * @throws IOException
   *           if the transmission failed.
   */
  private byte[] send(byte[] request, URL responderUrl, RequestOptions requestOptions)
      throws IOException {
    Args.notNull(responderUrl, "responderUrl");

    int size = Args.notNull(request, "request").length;
    HttpURLConnection httpUrlConnection;
    if (size <= MAX_LEN_GET &&
        Args.notNull(requestOptions, "requestOptions").isUseHttpGetForRequest()) {
      String b64Request = Base64.getEncoder().encodeToString(request);
      String urlEncodedReq = URLEncoder.encode(b64Request, StandardCharsets.UTF_8);
      String baseUrl = responderUrl.toString();
      String url = StringUtil.concat(baseUrl, (baseUrl.endsWith("/") ? "" : "/"), urlEncodedReq);

      URL newUrl = new URL(url);
      httpUrlConnection = IoUtil.openHttpConn(newUrl);
      httpUrlConnection.setRequestMethod("GET");
    } else {
      httpUrlConnection = IoUtil.openHttpConn(responderUrl);
      httpUrlConnection.setDoOutput(true);
      httpUrlConnection.setUseCaches(false);

      httpUrlConnection.setRequestMethod("POST");
      httpUrlConnection.setRequestProperty("Content-Type", CT_REQUEST);
      httpUrlConnection.setRequestProperty("Content-Length", Integer.toString(size));
      OutputStream outputstream = httpUrlConnection.getOutputStream();
      outputstream.write(request);
      outputstream.flush();
    }

    httpUrlConnection.setConnectTimeout(Curl.DEFAULT_CONNECT_TIMEOUT_MS);
    httpUrlConnection.setReadTimeout(Curl.DEFAULT_READ_TIMEOUT_MS);

    InputStream inputstream = httpUrlConnection.getInputStream();
    if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
      inputstream.close();
      throw new IOException("bad response: "
          + httpUrlConnection.getResponseCode() + "    "
          + httpUrlConnection.getResponseMessage());
    }

    String responseContentType = httpUrlConnection.getContentType();
    boolean isValidContentType = false;
    if (responseContentType != null) {
      if (responseContentType.equalsIgnoreCase(CT_RESPONSE)) {
        isValidContentType = true;
      }
    }

    if (!isValidContentType) {
      inputstream.close();
      throw new IOException("bad response: mime type " + responseContentType + " not supported!");
    }

    return XipkiIoUtil.readAllBytesAndClose(inputstream);
  } // method send

  public String confFile() {
    return confFile;
  }

  public void setConfFile(String confFile) {
    this.confFile = confFile;
  }

  public void init() {
    if (this.initFinished.get()) {
      return;
    }

    initSucc.set(false);

    try {
      LOG.info("initializing ...");

      if (securityFactory() == null) {
        LOG.error("securityFactory is not set");
      } else if (confFile == null) {
        LOG.info("confFile is not set, no signer will be created");
        initSucc.set(true);
      } else {
        doInit();
        initSucc.set(true);
        LOG.info("initialized");
      }
    } catch (Exception e) {
      LOG.error("Initializing failed", e);
    } finally {
      initFinished.set(true);
    }
  }

  private void doInit() throws Exception {
    File configFile = new File(IoUtil.expandFilepath(confFile));
    if (!configFile.exists()) {
      LOG.info("confFile {} does not exist, no signer will be created", configFile);
      return;
    }

    OcspRequestorConf conf = parse(configFile);
    String signerType = conf.signerType();
    String signerConf = conf.signerConf();
    FileOrBinary signerCert = conf.signerCert();

    if (StringUtil.isBlank(signerType)) {
      throw new OcspRequestorException("signerType is not configured");
    }

    if (StringUtil.isBlank(signerConf)) {
      throw new OcspRequestorException("signerConf is not configured");
    }

    X509Cert cert = null;
    if (signerCert != null) {
      try {
        cert = X509Util.parseCert(signerCert.readContent());
      } catch (CertificateException ex) {
        throw new OcspRequestorException("could not parse certificate: " + ex.getMessage());
      }
    }

    try {
      signer = securityFactory().createSigner(signerType, new SignerConf(signerConf), cert);
    } catch (Exception ex) {
      throw new OcspRequestorException("could not create signer: " + ex.getMessage());
    }
  }

  public void close() {
  }

  private ConcurrentSigner signer() throws OcspRequestorException {
    if (signer != null) {
      return signer;
    }

    if (!initFinished.get()) {
      throw new OcspRequestorException("Please initialize the OcspRequestor first");
    }

    if (!initSucc.get()) {
      throw new OcspRequestorException("Initialization of OcspRequestor failed");
    }

    throw new OcspRequestorException("No signer is configured");
  }

  private static OcspRequestorConf parse(File configFile) throws OcspRequestorException {
    OcspRequestorConf conf;
    try {
      JsonMap root = JsonParser.parseMap(configFile.toPath(), true);
      conf = OcspRequestorConf.parse(root);
    } catch (RuntimeException | CodecException ex) {
      throw new OcspRequestorException("parsing profile failed, message: " + ex.getMessage(), ex);
    }

    return conf;
  }

  @Override
  public OCSPResponse ask(X509Cert issuerCert, X509Cert cert, URL responderUrl,
                          RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException {
    if (!X509Util.issues(Args.notNull(issuerCert, "issuerCert"),
          Args.notNull(cert, "cert"))) {
      throw new IllegalArgumentException("cert and issuerCert do not match");
    }

    return ask(issuerCert, new BigInteger[]{cert.serialNumber()},
        responderUrl, requestOptions, debug);
  }

  @Override
  public OCSPResponse ask(X509Cert issuerCert, X509Cert[] certs, URL responderUrl,
                          RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException {
    Args.notNull(issuerCert, "issuerCert");
    Args.notNull(certs, "certs");
    Args.positive(certs.length, "certs.length");

    BigInteger[] serialNumbers = new BigInteger[certs.length];
    for (int i = 0; i < certs.length; i++) {
      X509Cert cert = certs[i];
      if (!X509Util.issues(issuerCert, cert)) {
        throw new IllegalArgumentException("cert at index " + i
            + " and issuerCert do not match");
      }
      serialNumbers[i] = cert.serialNumber();
    }

    return ask(issuerCert, serialNumbers, responderUrl, requestOptions, debug);
  }

  @Override
  public OCSPResponse ask(X509Cert issuerCert, BigInteger serialNumber,
                          URL responderUrl, RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException {
    return ask(issuerCert, new BigInteger[]{serialNumber}, responderUrl, requestOptions, debug);
  }

  @Override
  public OCSPResponse ask(X509Cert issuerCert, BigInteger[] serialNumbers,
                          URL responderUrl, RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException {
    Args.notNull(issuerCert, "issuerCert");
    Args.notNull(responderUrl, "responderUrl");

    byte[] nonce = null;
    if (Args.notNull(requestOptions, "requestOptions").isUseNonce()) {
      nonce = nextNonce(requestOptions.nonceLen());
    }

    OCSPRequest ocspReq = buildRequest(issuerCert, serialNumbers, nonce, requestOptions);
    byte[] encodedReq = ocspReq.getEncoded();

    ReqRespPair msgPair = null;
    if (debug != null) {
      msgPair = new ReqRespPair();
      debug.add(msgPair);
      if (debug.saveRequest()) {
        msgPair.setRequest(encodedReq);
      }
    }

    byte[] encodedResp;
    try {
      encodedResp = send(encodedReq, responderUrl, requestOptions);
    } catch (IOException ex) {
      throw new OcspResponseException.ResponderUnreachable("IOException: " + ex.getMessage(), ex);
    }

    if (msgPair != null && debug.saveResponse()) {
      msgPair.setResponse(encodedResp);
    }

    OCSPResponse ocspResp;
    try {
      ocspResp = OCSPResponse.fromEncoded(encodedResp);
    } catch (CodecException ex) {
      throw new OcspResponseException.InvalidResponse("IOException: " + ex.getMessage(), ex);
    }

    if (!ocspResp.getResponseStatus().equals(OCSPResponseStatus.SUCCESSFUL)) {
      return ocspResp;
    }

    BasicOCSPResponse basicOcspResp = ocspResp.getBasicOCSPResponse();
    if (basicOcspResp == null) {
      return ocspResp;
    }

    if (nonce != null) {
      Extension nonceExtn = basicOcspResp.getExtension(OcspOIDs.id_pkix_ocsp_nonce);
      if (nonceExtn == null) {
        if (!requestOptions.isAllowNoNonceInResponse()) {
          throw new OcspResponseException.OcspNonceUnmatched(nonce, null);
        }
      } else {
        byte[] receivedNonce = nonceExtn.ocspNonce();
        if (!Arrays.equals(nonce, receivedNonce)) {
          throw new OcspResponseException.OcspNonceUnmatched(nonce, receivedNonce);
        }
      }
    }

    SingleResponse.Seq0 singleResponses = basicOcspResp.getTbsResponseData().getResponses();
    if (singleResponses == null || singleResponses.isEmpty()) {
      String msg = StringUtil.concat(
          "response with no singleResponse is returned, expected is ",
          Integer.toString(serialNumbers.length));
      throw new OcspResponseException.OcspTargetUnmatched(msg);
    }

    final int countSingleResponses = singleResponses.size();

    if (countSingleResponses != serialNumbers.length) {
      String msg = StringUtil.concat("response with ", Integer.toString(countSingleResponses),
          " singleResponse", (countSingleResponses > 1 ? "s" : ""),
          " is returned, expected is ", Integer.toString(serialNumbers.length));
      throw new OcspResponseException.OcspTargetUnmatched(msg);
    }

    Request reqAt0 = ocspReq.getTbsRequest().getRequestList().get(0);

    CertID certId = reqAt0.getReqCert();
    Asn1Oid issuerHashAlg = certId.getHashAlgorithm().getAlgorithm();
    byte[] issuerKeyHash = certId.issuerKeyHash();
    byte[] issuerNameHash = certId.issuerNameHash();

    if (serialNumbers.length == 1) {
      SingleResponse singleResp = singleResponses.get(0);
      CertID cid = singleResp.getCertID();
      boolean issuerMatch = issuerHashAlg.equals(cid.getHashAlgorithm().getAlgorithm())
          && Arrays.equals(issuerKeyHash,  cid.issuerKeyHash())
          && Arrays.equals(issuerNameHash, cid.issuerNameHash());

      if (!issuerMatch) {
        throw new OcspResponseException.OcspTargetUnmatched("the issuer is not requested");
      }

      BigInteger serialNumber = cid.serialNumber();
      if (!serialNumbers[0].equals(serialNumber)) {
        throw new OcspResponseException.OcspTargetUnmatched("the serialNumber is not requested");
      }
    } else {
      List<BigInteger> tmpSerials1 = Arrays.asList(serialNumbers);
      List<BigInteger> tmpSerials2 = new ArrayList<>(tmpSerials1);

      for (int i = 0; i < countSingleResponses; i++) {
        SingleResponse singleResp = singleResponses.get(i);
        CertID cid = singleResp.getCertID();
        boolean issuerMatch = issuerHashAlg.equals(cid.getHashAlgorithm().getAlgorithm())
            && Arrays.equals(issuerKeyHash, cid.issuerKeyHash())
            && Arrays.equals(issuerNameHash, cid.issuerNameHash());

        if (!issuerMatch) {
          throw new OcspResponseException.OcspTargetUnmatched(
              "the issuer specified in singleResponse[" + i + "] is not requested");
        }

        BigInteger serialNumber = cid.serialNumber();
        if (!tmpSerials2.remove(serialNumber)) {
          if (tmpSerials1.contains(serialNumber)) {
            throw new OcspResponseException.OcspTargetUnmatched(
                "serialNumber " + LogUtil.formatCsn(serialNumber)
                + "is contained in at least two singleResponses");
          } else {
            throw new OcspResponseException.OcspTargetUnmatched(
                "serialNumber " + LogUtil.formatCsn(serialNumber) + " specified in "
                + "singleResponse[" + i + "] is not requested");
          }
        }
      } // end for
    } // end if

    return ocspResp;
  } // method ask

  private OCSPRequest buildRequest(
      X509Cert caCert, BigInteger[] serialNumbers, byte[] nonce, RequestOptions requestOptions)
      throws OcspRequestorException {
    HashAlgo hashAlgo = requestOptions.hashAlgorithm();
    List<SignAlgo> prefSigAlgs = requestOptions.preferredSignatureAlgorithms();

    XiOCSPReqBuilder reqBuilder = new XiOCSPReqBuilder();
    List<Extension> extensions = new LinkedList<>();
    if (nonce != null) {
      extensions.add(Extension.ofOcspNonce(false, nonce));
    }

    if (prefSigAlgs != null && !prefSigAlgs.isEmpty()) {
      List<PreferredSignatureAlgorithm> vec = new LinkedList<>();
      for (SignAlgo algId : prefSigAlgs) {
        vec.add(new PreferredSignatureAlgorithm(algId.algorithmIdentifier()));
      }

      Extension extn = Extension.ofPreferredSignatureAlgorithms(false,
          new PreferredSignatureAlgorithms(vec));
      extensions.add(extn);
    }

    if (CollectionUtil.isNotEmpty(extensions)) {
      reqBuilder.setRequestExtensions(new Extensions(extensions.toArray(new Extension[0])));
    }

    try {
      Asn1OctetString issuerNameHash =
          new Asn1OctetString(hashAlgo.hash(caCert.subject().getEncoded()));

      TBSCertificate tbsCert = caCert.getCert().getTBSCertificate();
      Asn1OctetString issuerKeyHash = new Asn1OctetString(
          hashAlgo.hash(tbsCert.getSubjectPublicKeyInfo().subjectPublicKey()));

      for (BigInteger serialNumber : serialNumbers) {
        CertID certId = new CertID(hashAlgo.algorithmIdentifier(),
            issuerNameHash, issuerKeyHash, new Asn1Integer(serialNumber));

        reqBuilder.addRequest(certId);
      }

      if (requestOptions.isSignRequest()) {
        ConcurrentSigner signer = signer();

        reqBuilder.setRequestorName(signer.x509Cert().subject());
        X509Cert[] certChain0 = signer.x509CertChain();
        Certificate[] certChain = new Certificate[certChain0.length];
        for (int i = 0; i < certChain.length; i++) {
          certChain[i] = certChain0[i].getCert();
        }

        Signer signer0;
        try {
          signer0 = signer.borrowSigner();
        } catch (NoIdleSignerException ex) {
          throw new OcspRequestorException("NoIdleSignerException: " + ex.getMessage());
        }

        try {
          return reqBuilder.build(signer0.x509Signer(), certChain);
        } finally {
          signer.requiteSigner(signer0);
        }
      } else {
        return reqBuilder.build();
      } // end if
    } catch (OCSPException ex) {
      throw new OcspRequestorException(ex.getMessage(), ex);
    }
  } // method buildRequest

  private byte[] nextNonce(int nonceLen) {
    byte[] nonce = new byte[nonceLen];
    random.nextBytes(nonce);
    return nonce;
  }

  public SecurityFactory securityFactory() {
    return securityFactory;
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

}
