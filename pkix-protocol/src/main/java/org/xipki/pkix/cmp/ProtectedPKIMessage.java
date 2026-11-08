// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp;

import org.xipki.asn1.cmp.CMPCertificate;
import org.xipki.asn1.cmp.InfoTypeAndValue;
import org.xipki.asn1.cmp.PBMParameter;
import org.xipki.asn1.cmp.PKIBody;
import org.xipki.asn1.cmp.PKIFreeText;
import org.xipki.asn1.cmp.PKIHeader;
import org.xipki.asn1.cmp.PKIMessage;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.CmpOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.util.exception.PkixException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A protected CMP PKIMessage, protected by signature or by password-based MAC (RFC 4210,
 * section 5.1.3).
 *
 * @author Lijun Liao (xipki)
 */
public class ProtectedPKIMessage {

  /**
   * Default maximal PBMParameter.iterationCount accepted by {@link #verify(char[])}.
   */
  public static final int DFLT_MAX_PBM_ITERATION_COUNT = 1_000_000;

  /**
   * Minimal PBMParameter.iterationCount accepted by {@link #verify(char[], int)}.
   */
  public static final int MIN_PBM_ITERATION_COUNT = 1000;

  private static final CryptoApi crypto = CryptoApiFactory.get();

  private final PKIMessage pkiMessage;

  public ProtectedPKIMessage(PKIMessage pkiMessage) {
    if (Args.notNull(pkiMessage, "pkiMessage").getHeader().getProtectionAlg() == null) {
      throw new IllegalArgumentException("PKIMessage not protected");
    }
    this.pkiMessage = pkiMessage;
  }

  public PKIHeader getHeader() {
    return pkiMessage.getHeader();
  }

  public PKIMessage toASN1Structure() {
    return pkiMessage;
  }

  public boolean hasPasswordBasedMacProtection() {
    return CmpOIDs.passwordBasedMac.equals(protectionAlg().getAlgorithm());
  }

  /**
   * Verifies the signature-based protection.
   * @param verifierProvider the provider of the signature verifier.
   * @return true if the signature is valid, false otherwise.
   * @throws PkixException if the signature cannot be verified.
   */
  public boolean verify(ContentVerifierProvider verifierProvider) throws PkixException {
    try {
      ContentVerifier verifier = verifierProvider.get(protectionAlg());
      return verifier.atomicVerify(protectedPart(pkiMessage.getHeader(), pkiMessage.getBody()),
          pkiMessage.protection());
    } catch (Exception e) {
      throw new PkixException("unable to verify signature: " + e.getMessage(), e);
    }
  }

  /**
   * Verifies the password-based MAC protection.
   * @param password the password.
   * @return true if the MAC is valid, false otherwise.
   * @throws PkixException if the MAC cannot be verified, or the iteration count exceeds
   *         {@link #DFLT_MAX_PBM_ITERATION_COUNT}.
   */
  public boolean verify(char[] password) throws PkixException {
    return verify(password, DFLT_MAX_PBM_ITERATION_COUNT);
  }

  /**
   * Verifies the password-based MAC protection.
   * @param password the password.
   * @param maxIterationCount the maximal iteration count. A message with larger
   *        PBMParameter.iterationCount is rejected, since the hash is computed iterationCount
   *        times before the MAC can be verified.
   * @return true if the MAC is valid, false otherwise.
   * @throws PkixException if the MAC cannot be verified, or the iteration count exceeds
   *         maxIterationCount.
   */
  public boolean verify(char[] password, int maxIterationCount) throws PkixException {
    AlgorithmIdentifier protectionAlg = protectionAlg();
    if (!CmpOIDs.passwordBasedMac.equals(protectionAlg.getAlgorithm())) {
      throw new PkixException("protection algorithm is not passwordBasedMac");
    }

    PBMParameter params;
    try {
      params = PBMParameter.fromAsn1(protectionAlg.getParameters().asSequence());
    } catch (CodecException | RuntimeException e) {
      throw new PkixException("invalid PBMParameter: " + e.getMessage(), e);
    }

    if (params.iterationCount() < MIN_PBM_ITERATION_COUNT) {
      throw new PkixException("PBMParameter.iterationCount " + params.iterationCount()
          + " is less than the minimal " + MIN_PBM_ITERATION_COUNT);
    }

    if (params.iterationCount() > maxIterationCount) {
      throw new PkixException("PBMParameter.iterationCount " + params.iterationCount()
          + " exceeds the maximal " + maxIterationCount);
    }

    byte[] mac = calculatePbmac(params, password,
                    protectedPart(pkiMessage.getHeader(), pkiMessage.getBody()));
    return MessageDigest.isEqual(mac, pkiMessage.protection());
  }

  private AlgorithmIdentifier protectionAlg() {
    return pkiMessage.getHeader().getProtectionAlg();
  }

  /**
   * Returns the DER encoding of ProtectedPart ::= SEQUENCE { header, body }.
   */
  private static byte[] protectedPart(PKIHeader header, PKIBody body) {
    return new PKIMessage(header, body).getEncoded();
  }

  /**
   * Calculates the password-based MAC (RFC 4210, section 5.1.3.1).
   */
  private static byte[] calculatePbmac(PBMParameter params, char[] password, byte[] data)
      throws PkixException {
    Args.notNull(password, "password");
    ByteBuffer pwBuf = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    byte[] pw = Arrays.copyOfRange(pwBuf.array(), pwBuf.position(), pwBuf.limit());
    Arrays.fill(pwBuf.array(), (byte) 0);

    byte[] salt = params.salt();
    byte[] key = new byte[pw.length + salt.length];
    System.arraycopy(pw, 0, key, 0, pw.length);
    System.arraycopy(salt, 0, key, pw.length, salt.length);
    Arrays.fill(pw, (byte) 0);

    try {
      MessageDigest owf = crypto.newMessageDigest(params.getOwf().getAlgorithm().getId());
      for (int i = params.iterationCount(); i > 0; i--) {
        key = owf.digest(key);
      }

      Mac mac = crypto.newMac(params.getMac().getAlgorithm().getId());
      mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
      return mac.doFinal(data);
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new PkixException("could not calculate the password-based MAC: "
          + e.getMessage(), e);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  /**
   * Builder of the protected PKIMessage.
   */
  public static class Builder {

    private final PKIHeader header;

    private PKIBody body;

    private final List<InfoTypeAndValue> generalInfos = new ArrayList<>();

    private final List<Certificate> extraCerts = new ArrayList<>();

    public Builder(GeneralName sender, GeneralName recipient) {
      this(PKIHeader.CMP_2000, sender, recipient);
    }

    public Builder(int pvno, GeneralName sender, GeneralName recipient) {
      header = new PKIHeader(pvno, sender, recipient);
    }

    public Builder setTransactionID(byte[] tid) {
      header.setTransactionID(tid);
      return this;
    }

    public Builder setFreeText(PKIFreeText freeText) {
      header.setFreeText(freeText);
      return this;
    }

    public Builder addGeneralInfo(InfoTypeAndValue genInfo) {
      generalInfos.add(genInfo);
      return this;
    }

    public Builder setMessageTime(Instant time) {
      header.setMessageTime(time);
      return this;
    }

    public Builder setRecipKID(byte[] kid) {
      header.setRecipKID(kid);
      return this;
    }

    public Builder setRecipNonce(byte[] nonce) {
      header.setRecipNonce(nonce);
      return this;
    }

    public Builder setSenderKID(byte[] kid) {
      header.setSenderKID(kid);
      return this;
    }

    public Builder setSenderNonce(byte[] nonce) {
      header.setSenderNonce(nonce);
      return this;
    }

    public Builder setBody(PKIBody body) {
      this.body = body;
      return this;
    }

    public Builder addCMPCertificate(Certificate extraCert) {
      extraCerts.add(extraCert);
      return this;
    }

    /**
     * Builds the message protected by the password-based MAC.
     * @param params the PBM parameters.
     * @param password the password.
     * @return the protected message.
     * @throws PkixException if the MAC cannot be calculated.
     */
    public ProtectedPKIMessage build(PBMParameter params, char[] password) throws PkixException {
      Args.notNull(params, "params");
      finaliseHeader(AlgorithmIdentifier.build(CmpOIDs.passwordBasedMac, params));
      byte[] mac = calculatePbmac(params, password, protectedPart(header, body));
      return finaliseMessage(new Asn1BitString(mac));
    }

    /**
     * Builds the message protected by signature.
     * @param signer the signer.
     * @return the protected message.
     * @throws PkixException if the signature cannot be calculated.
     */
    public ProtectedPKIMessage build(ContentSigner signer) throws PkixException {
      Args.notNull(signer, "signer");
      finaliseHeader(signer.getAlgorithmIdentifier());
      try {
        byte[] signature = signer.atomicSign(protectedPart(header, body));
        return finaliseMessage(new Asn1BitString(signature));
      } catch (SignatureException e) {
        throw new PkixException("unable to sign: " + e.getMessage(), e);
      }
    }

    private void finaliseHeader(AlgorithmIdentifier protectionAlg) {
      if (body == null) {
        throw new IllegalStateException("body must be set before building");
      }

      header.setProtectionAlg(protectionAlg);
      if (!generalInfos.isEmpty()) {
        header.setGeneralInfo(new InfoTypeAndValue.Seq1(generalInfos));
      }
    }

    private ProtectedPKIMessage finaliseMessage(Asn1BitString protection) {
      if (extraCerts.isEmpty()) {
        return new ProtectedPKIMessage(new PKIMessage(header, body, protection));
      }

      CMPCertificate[] cmpCerts = new CMPCertificate[extraCerts.size()];
      for (int i = 0; i < cmpCerts.length; i++) {
        cmpCerts[i] = CMPCertificate.ofX509v3PKCert(extraCerts.get(i));
      }
      return new ProtectedPKIMessage(new PKIMessage(header, body, protection,
          new CMPCertificate.Seq1(cmpCerts)));
    }

  }

}
