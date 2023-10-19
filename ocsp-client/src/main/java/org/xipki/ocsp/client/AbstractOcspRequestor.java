// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.ocsp.*;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.ReqRespDebug.ReqRespPair;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Abstract class of OCSP requestor.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class AbstractOcspRequestor implements OcspRequestor {

  private SecurityFactory securityFactory;

  private final Object signerLock = new Object();

  private ConcurrentContentSigner signer;

  private String signerType;

  private String signerConf;

  private String signerCertFile;

  private final SecureRandom random = new SecureRandom();

  protected AbstractOcspRequestor() {
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
  protected abstract byte[] send(byte[] request, URL responderUrl, RequestOptions requestOptions)
      throws IOException;

  @Override
  public OCSPResp ask(X509Cert issuerCert, X509Cert cert, URL responderUrl,
                      RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException {
    if (!X509Util.issues(Args.notNull(issuerCert, "issuerCert"), Args.notNull(cert, "cert"))) {
      throw new IllegalArgumentException("cert and issuerCert do not match");
    }

    return ask(issuerCert, new BigInteger[]{cert.getSerialNumber()}, responderUrl, requestOptions, debug);
  }

  @Override
  public OCSPResp ask(X509Cert issuerCert, X509Cert[] certs, URL responderUrl,
                      RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException {
    Args.notNull(issuerCert, "issuerCert");
    Args.notNull(certs, "certs");
    Args.positive(certs.length, "certs.length");

    BigInteger[] serialNumbers = new BigInteger[certs.length];
    for (int i = 0; i < certs.length; i++) {
      X509Cert cert = certs[i];
      if (!X509Util.issues(issuerCert, cert)) {
        throw new IllegalArgumentException("cert at index " + i + " and issuerCert do not match");
      }
      serialNumbers[i] = cert.getSerialNumber();
    }

    return ask(issuerCert, serialNumbers, responderUrl, requestOptions, debug);
  }

  @Override
  public OCSPResp ask(X509Cert issuerCert, BigInteger serialNumber, URL responderUrl,
                      RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException {
    return ask(issuerCert, new BigInteger[]{serialNumber}, responderUrl, requestOptions, debug);
  }

  @Override
  public OCSPResp ask(X509Cert issuerCert, BigInteger[] serialNumbers, URL responderUrl,
                      RequestOptions requestOptions, ReqRespDebug debug)
      throws OcspResponseException, OcspRequestorException {
    Args.notNull(issuerCert, "issuerCert");
    Args.notNull(responderUrl, "responderUrl");

    byte[] nonce = null;
    if (Args.notNull(requestOptions, "requestOptions").isUseNonce()) {
      nonce = nextNonce(requestOptions.getNonceLen());
    }

    OCSPRequest ocspReq = buildRequest(issuerCert, serialNumbers, nonce, requestOptions);
    byte[] encodedReq;
    try {
      encodedReq = ocspReq.getEncoded();
    } catch (IOException ex) {
      throw new OcspRequestorException("could not encode OCSP request: " + ex.getMessage(), ex);
    }

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

    OCSPResp ocspResp;
    try {
      ocspResp = new OCSPResp(encodedResp);
    } catch (IOException ex) {
      throw new OcspResponseException.InvalidResponse("IOException: " + ex.getMessage(), ex);
    }

    Object respObject;
    try {
      respObject = ocspResp.getResponseObject();
    } catch (OCSPException ex) {
      throw new OcspResponseException.InvalidResponse("responseObject is invalid");
    }

    if (ocspResp.getStatus() != 0) {
      return ocspResp;
    }

    if (!(respObject instanceof BasicOCSPResp)) {
      return ocspResp;
    }

    BasicOCSPResp basicOcspResp = (BasicOCSPResp) respObject;

    if (nonce != null) {
      Extension nonceExtn = basicOcspResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
      if (nonceExtn == null) {
        if (!requestOptions.isAllowNoNonceInResponse()) {
          throw new OcspResponseException.OcspNonceUnmatched(nonce, null);
        }
      } else {
        byte[] receivedNonce = nonceExtn.getExtnValue().getOctets();
        if (!Arrays.equals(nonce, receivedNonce)) {
          throw new OcspResponseException.OcspNonceUnmatched(nonce, receivedNonce);
        }
      }
    }

    SingleResp[] singleResponses = basicOcspResp.getResponses();
    if (singleResponses == null || singleResponses.length == 0) {
      String msg = StringUtil.concat("response with no singleResponse is returned, expected is ",
          Integer.toString(serialNumbers.length));
      throw new OcspResponseException.OcspTargetUnmatched(msg);
    }

    final int countSingleResponses = singleResponses.length;

    if (countSingleResponses != serialNumbers.length) {
      String msg = StringUtil.concat("response with ", Integer.toString(countSingleResponses),
          " singleResponse", (countSingleResponses > 1 ? "s" : ""),
          " is returned, expected is ", Integer.toString(serialNumbers.length));
      throw new OcspResponseException.OcspTargetUnmatched(msg);
    }

    Request reqAt0 = Request.getInstance(ocspReq.getTbsRequest().getRequestList().getObjectAt(0));

    CertID certId = reqAt0.getReqCert();
    ASN1ObjectIdentifier issuerHashAlg = certId.getHashAlgorithm().getAlgorithm();
    byte[] issuerKeyHash = certId.getIssuerKeyHash().getOctets();
    byte[] issuerNameHash = certId.getIssuerNameHash().getOctets();

    if (serialNumbers.length == 1) {
      SingleResp singleResp = singleResponses[0];
      CertificateID cid = singleResp.getCertID();
      boolean issuerMatch = issuerHashAlg.equals(cid.getHashAlgOID())
          && Arrays.equals(issuerKeyHash, cid.getIssuerKeyHash())
          && Arrays.equals(issuerNameHash, cid.getIssuerNameHash());

      if (!issuerMatch) {
        throw new OcspResponseException.OcspTargetUnmatched("the issuer is not requested");
      }

      BigInteger serialNumber = cid.getSerialNumber();
      if (!serialNumbers[0].equals(serialNumber)) {
        throw new OcspResponseException.OcspTargetUnmatched("the serialNumber is not requested");
      }
    } else {
      List<BigInteger> tmpSerials1 = Arrays.asList(serialNumbers);
      List<BigInteger> tmpSerials2 = new ArrayList<>(tmpSerials1);

      for (int i = 0; i < countSingleResponses; i++) {
        SingleResp singleResp = singleResponses[i];
        CertificateID cid = singleResp.getCertID();
        boolean issuerMatch = issuerHashAlg.equals(cid.getHashAlgOID())
            && Arrays.equals(issuerKeyHash, cid.getIssuerKeyHash())
            && Arrays.equals(issuerNameHash, cid.getIssuerNameHash());

        if (!issuerMatch) {
          throw new OcspResponseException.OcspTargetUnmatched(
              "the issuer specified in singleResponse[" + i + "] is not requested");
        }

        BigInteger serialNumber = cid.getSerialNumber();
        if (!tmpSerials2.remove(serialNumber)) {
          if (tmpSerials1.contains(serialNumber)) {
            throw new OcspResponseException.OcspTargetUnmatched("serialNumber "
                + LogUtil.formatCsn(serialNumber) + "is contained in at least two singleResponses");
          } else {
            throw new OcspResponseException.OcspTargetUnmatched("serialNumber "
                + LogUtil.formatCsn(serialNumber) + " specified in singleResponse[" + i + "] is not requested");
          }
        }
      } // end for
    } // end if

    return ocspResp;
  } // method ask

  private OCSPRequest buildRequest(
      X509Cert caCert, BigInteger[] serialNumbers, byte[] nonce, RequestOptions requestOptions)
      throws OcspRequestorException {
    HashAlgo hashAlgo = requestOptions.getHashAlgorithm();
    List<SignAlgo> prefSigAlgs = requestOptions.getPreferredSignatureAlgorithms();

    XiOCSPReqBuilder reqBuilder = new XiOCSPReqBuilder();
    List<Extension> extensions = new LinkedList<>();
    if (nonce != null) {
      extensions.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce)));
    }

    if (prefSigAlgs != null && prefSigAlgs.size() > 0) {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (SignAlgo algId : prefSigAlgs) {
        vec.add(new DERSequence(algId.getAlgorithmIdentifier()));
      }

      ASN1Sequence extnValue = new DERSequence(vec);
      Extension extn;
      try {
        extn = new Extension(ObjectIdentifiers.Extn.id_pkix_ocsp_prefSigAlgs, false, new DEROctetString(extnValue));
      } catch (IOException ex) {
        throw new OcspRequestorException(ex.getMessage(), ex);
      }
      extensions.add(extn);
    }

    if (CollectionUtil.isNotEmpty(extensions)) {
      reqBuilder.setRequestExtensions(new Extensions(extensions.toArray(new Extension[0])));
    }

    try {
      DEROctetString issuerNameHash = new DEROctetString(hashAlgo.hash(caCert.getSubject().getEncoded()));

      TBSCertificate tbsCert = caCert.toBcCert().toASN1Structure().getTBSCertificate();
      DEROctetString issuerKeyHash = new DEROctetString(hashAlgo.hash(
          tbsCert.getSubjectPublicKeyInfo().getPublicKeyData().getOctets()));

      for (BigInteger serialNumber : serialNumbers) {
        CertID certId = new CertID(hashAlgo.getAlgorithmIdentifier(), issuerNameHash, issuerKeyHash,
            new ASN1Integer(serialNumber));

        reqBuilder.addRequest(certId);
      }

      if (requestOptions.isSignRequest()) {
        synchronized (signerLock) {
          if (signer == null) {
            if (StringUtil.isBlank(signerType)) {
              throw new OcspRequestorException("signerType is not configured");
            }

            if (StringUtil.isBlank(signerConf)) {
              throw new OcspRequestorException("signerConf is not configured");
            }

            X509Cert cert = null;
            if (StringUtil.isNotBlank(signerCertFile)) {
              try {
                cert = X509Util.parseCert(new File(signerCertFile));
              } catch (CertificateException ex) {
                throw new OcspRequestorException(
                    "could not parse certificate " + signerCertFile + ": " + ex.getMessage());
              }
            }

            try {
              signer = getSecurityFactory().createSigner(signerType, new SignerConf(signerConf), cert);
            } catch (Exception ex) {
              throw new OcspRequestorException("could not create signer: " + ex.getMessage());
            }
          } // end if
        } // end synchronized

        reqBuilder.setRequestorName(signer.getCertificate().getSubject());
        X509Cert[] certChain0 = signer.getCertificateChain();
        Certificate[] certChain = new Certificate[certChain0.length];
        for (int i = 0; i < certChain.length; i++) {
          certChain[i] = certChain0[i].toBcCert().toASN1Structure();
        }

        ConcurrentBag.BagEntry<XiContentSigner> signer0;
        try {
          signer0 = signer.borrowSigner();
        } catch (NoIdleSignerException ex) {
          throw new OcspRequestorException("NoIdleSignerException: " + ex.getMessage());
        }

        try {
          return reqBuilder.build(signer0.value(), certChain);
        } finally {
          signer.requiteSigner(signer0);
        }
      } else {
        return reqBuilder.build();
      } // end if
    } catch (OCSPException | IOException ex) {
      throw new OcspRequestorException(ex.getMessage(), ex);
    }
  } // method buildRequest

  private byte[] nextNonce(int nonceLen) {
    byte[] nonce = new byte[nonceLen];
    random.nextBytes(nonce);
    return nonce;
  }

  public String getSignerConf() {
    return signerConf;
  }

  public void setSignerConf(String signerConf) {
    this.signer = null;
    this.signerConf = signerConf;
  }

  public String getSignerCertFile() {
    return signerCertFile;
  }

  public void setSignerCertFile(String signerCertFile) {
    if (StringUtil.isNotBlank(signerCertFile)) {
      this.signer = null;
      this.signerCertFile = signerCertFile;
    }
  }

  public String getSignerType() {
    return signerType;
  }

  public void setSignerType(String signerType) {
    this.signer = null;
    this.signerType = signerType;
  }

  public SecurityFactory getSecurityFactory() {
    return securityFactory;
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

}
