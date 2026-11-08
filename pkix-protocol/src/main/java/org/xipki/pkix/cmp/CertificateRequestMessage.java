// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp;

import org.xipki.asn1.crmf.CertReqMsg;
import org.xipki.asn1.crmf.CertRequest;
import org.xipki.asn1.crmf.CertTemplate;
import org.xipki.asn1.crmf.POPOSigningKey;
import org.xipki.asn1.crmf.ProofOfPossession;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.Args;
import org.xipki.util.exception.PkixException;

import java.security.SignatureException;

/**
 * CRMF certificate request message (RFC 4211) and its signing-key proof of possession.
 *
 * @author Lijun Liao (xipki)
 */
public class CertificateRequestMessage {

  public static final int tag_popRaVerified = ProofOfPossession.tag_raVerified;

  public static final int tag_popSigningKey = ProofOfPossession.tag_signature;

  private final CertReqMsg certReqMsg;

  public CertificateRequestMessage(CertReqMsg certReqMsg) {
    this.certReqMsg = Args.notNull(certReqMsg, "certReqMsg");
  }

  public CertReqMsg toASN1Structure() {
    return certReqMsg;
  }

  public CertTemplate getCertTemplate() {
    return certReqMsg.getCertReq().getCertTemplate();
  }

  public boolean hasProofOfPossession() {
    return certReqMsg.getPop() != null;
  }

  public int getProofOfPossessionType() {
    return certReqMsg.getPop().getTagNo();
  }

  /**
   * Verifies the signing-key proof of possession whose POPOSigningKeyInput, if present,
   * contains the sender (RFC 4211, section 4.1).
   * @param verifierProvider the provider of the signature verifier.
   * @return true if the signature is valid, false otherwise.
   * @throws PkixException if the signature cannot be verified.
   */
  public boolean isValidSigningKeyPOP(ContentVerifierProvider verifierProvider)
      throws PkixException {
    ProofOfPossession pop = certReqMsg.getPop();
    if (pop.getTagNo() != tag_popSigningKey) {
      throw new IllegalStateException("not Signing Key type of proof of possession");
    }

    POPOSigningKey popoSign = pop.getSignature();
    if (popoSign.getPoposkInput() != null
        && popoSign.getPoposkInput().getPublicKeyMAC() != null) {
      throw new IllegalStateException("verification requires password check");
    }

    Asn1Encodable signed = popoSign.getPoposkInput();
    if (signed == null) {
      signed = certReqMsg.getCertReq();
    }

    try {
      ContentVerifier verifier = verifierProvider.get(popoSign.getAlgorithmIdentifier());
      return verifier.atomicVerify(signed.getEncoded(), popoSign.signature());
    } catch (Exception e) {
      throw new PkixException("error verifying the signature: " + e.getMessage(), e);
    }
  }

  /**
   * Builds the signing-key proof of possession over the CertRequest, i.e. without
   * POPOSigningKeyInput (RFC 4211, section 4.1).
   * @param certRequest the certificate request.
   * @param signer the signer with the private key of the requested certificate.
   * @return the proof of possession.
   * @throws PkixException if the signature cannot be calculated.
   */
  public static POPOSigningKey buildSigningKeyPop(CertRequest certRequest, ContentSigner signer)
      throws PkixException {
    Args.notNull(certRequest, "certRequest");
    Args.notNull(signer, "signer");
    try {
      byte[] signature = signer.atomicSign(certRequest.getEncoded());
      return new POPOSigningKey(null, signer.getAlgorithmIdentifier(), signature);
    } catch (SignatureException e) {
      throw new PkixException("error signing: " + e.getMessage(), e);
    }
  }

}
