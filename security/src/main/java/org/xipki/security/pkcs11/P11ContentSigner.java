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

package org.xipki.security.pkcs11;

import static org.xipki.util.Args.notNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.LogUtil;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * PKCS#11 {@link XiContentSigner}.
 *
 * @author Lijun Liao
 *
 */
abstract class P11ContentSigner implements XiContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(P11ContentSigner.class);

  protected final P11CryptService cryptService;

  protected final P11IdentityId identityId;

  protected final AlgorithmIdentifier algorithmIdentifier;

  protected final byte[] encodedAlgorithmIdentifier;

  P11ContentSigner(P11CryptService cryptService, P11IdentityId identityId,
      AlgorithmIdentifier signatureAlgId)
      throws XiSecurityException, P11TokenException {
    this.identityId = notNull(identityId, "identityId");
    this.cryptService = notNull(cryptService, "cryptService");
    this.algorithmIdentifier = notNull(signatureAlgId, "signatureAlgId");
    try {
      this.encodedAlgorithmIdentifier = algorithmIdentifier.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
  }

  @Override
  public final AlgorithmIdentifier getAlgorithmIdentifier() {
    return algorithmIdentifier;
  }

  @Override
  public final byte[] getEncodedAlgorithmIdentifier() {
    return Arrays.copyOf(encodedAlgorithmIdentifier, encodedAlgorithmIdentifier.length);
  }

  // CHECKSTYLE:SKIP
  static class DSA extends P11ContentSigner {

    private static final Map<String, HashAlgo> sigAlgHashMap = new HashMap<>();

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    private final boolean plain;

    static {
      sigAlgHashMap.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), HashAlgo.SHA1);
      sigAlgHashMap.put(NISTObjectIdentifiers.dsa_with_sha224.getId(), HashAlgo.SHA224);
      sigAlgHashMap.put(NISTObjectIdentifiers.dsa_with_sha256.getId(), HashAlgo.SHA256);
      sigAlgHashMap.put(NISTObjectIdentifiers.dsa_with_sha384.getId(), HashAlgo.SHA384);
      sigAlgHashMap.put(NISTObjectIdentifiers.dsa_with_sha512.getId(), HashAlgo.SHA512);
      sigAlgHashMap.put(NISTObjectIdentifiers.id_dsa_with_sha3_224.getId(), HashAlgo.SHA3_224);
      sigAlgHashMap.put(NISTObjectIdentifiers.id_dsa_with_sha3_256.getId(), HashAlgo.SHA3_256);
      sigAlgHashMap.put(NISTObjectIdentifiers.id_dsa_with_sha3_384.getId(), HashAlgo.SHA3_384);
      sigAlgHashMap.put(NISTObjectIdentifiers.id_dsa_with_sha3_512.getId(), HashAlgo.SHA3_512);

      hashMechMap.put(HashAlgo.SHA1, PKCS11Constants.CKM_DSA_SHA1);
      hashMechMap.put(HashAlgo.SHA224, PKCS11Constants.CKM_DSA_SHA224);
      hashMechMap.put(HashAlgo.SHA256, PKCS11Constants.CKM_DSA_SHA256);
      hashMechMap.put(HashAlgo.SHA384, PKCS11Constants.CKM_DSA_SHA384);
      hashMechMap.put(HashAlgo.SHA512, PKCS11Constants.CKM_DSA_SHA512);
      hashMechMap.put(HashAlgo.SHA3_224, PKCS11Constants.CKM_DSA_SHA3_224);
      hashMechMap.put(HashAlgo.SHA3_256, PKCS11Constants.CKM_DSA_SHA3_256);
      hashMechMap.put(HashAlgo.SHA3_384, PKCS11Constants.CKM_DSA_SHA3_384);
      hashMechMap.put(HashAlgo.SHA3_512, PKCS11Constants.CKM_DSA_SHA3_512);
    } // method static

    DSA(P11CryptService cryptService, P11IdentityId identityId,
        AlgorithmIdentifier signatureAlgId, boolean plain)
        throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, signatureAlgId);

      this.plain = plain;

      String algOid = signatureAlgId.getAlgorithm().getId();
      HashAlgo hashAlgo = sigAlgHashMap.get(algOid);
      if (hashAlgo == null) {
        throw new XiSecurityException("unsupported signature algorithm " + algOid);
      }

      P11SlotIdentifier slotId = identityId.getSlotId();
      P11Slot slot = cryptService.getSlot(slotId);

      long mech = hashMechMap.get(hashAlgo).longValue();
      if (slot.supportsMechanism(mech)) {
        mechanism = mech;
        this.outputStream = new ByteArrayOutputStream();
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_DSA)) {
        mechanism = PKCS11Constants.CKM_DSA;
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + algOid);
      }
    } // constructor

    @Override
    public OutputStream getOutputStream() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
      }
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      try {
        byte[] plainSignature = getPlainSignature();
        return plain ? plainSignature : SignerUtil.dsaSigPlainToX962(plainSignature);
      } catch (XiSecurityException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("XiSecurityException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

    private byte[] getPlainSignature() throws XiSecurityException, P11TokenException {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
      }

      return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
    }

  } // class DSA

  // CHECKSTYLE:SKIP
  static class ECDSA extends P11ContentSigner {

    private static final Map<String, HashAlgo> sigAlgHashMap = new HashMap<>();

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    private final boolean plain;

    static {
      sigAlgHashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA1.getId(), HashAlgo.SHA1);
      sigAlgHashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA224.getId(), HashAlgo.SHA224);
      sigAlgHashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), HashAlgo.SHA256);
      sigAlgHashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA384.getId(), HashAlgo.SHA384);
      sigAlgHashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA512.getId(), HashAlgo.SHA512);
      sigAlgHashMap.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_224.getId(), HashAlgo.SHA3_224);
      sigAlgHashMap.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId(), HashAlgo.SHA3_256);
      sigAlgHashMap.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId(), HashAlgo.SHA3_384);
      sigAlgHashMap.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId(), HashAlgo.SHA3_512);

      sigAlgHashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA1.getId(), HashAlgo.SHA1);
      sigAlgHashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA224.getId(), HashAlgo.SHA224);
      sigAlgHashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA256.getId(), HashAlgo.SHA256);
      sigAlgHashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA384.getId(), HashAlgo.SHA384);
      sigAlgHashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA512.getId(), HashAlgo.SHA512);

      hashMechMap.put(HashAlgo.SHA1, PKCS11Constants.CKM_ECDSA_SHA1);
      hashMechMap.put(HashAlgo.SHA224, PKCS11Constants.CKM_ECDSA_SHA224);
      hashMechMap.put(HashAlgo.SHA256, PKCS11Constants.CKM_ECDSA_SHA256);
      hashMechMap.put(HashAlgo.SHA384, PKCS11Constants.CKM_ECDSA_SHA384);
      hashMechMap.put(HashAlgo.SHA512, PKCS11Constants.CKM_ECDSA_SHA512);
      hashMechMap.put(HashAlgo.SHA3_224, PKCS11Constants.CKM_ECDSA_SHA3_224);
      hashMechMap.put(HashAlgo.SHA3_256, PKCS11Constants.CKM_ECDSA_SHA3_256);
      hashMechMap.put(HashAlgo.SHA3_384, PKCS11Constants.CKM_ECDSA_SHA3_384);
      hashMechMap.put(HashAlgo.SHA3_512, PKCS11Constants.CKM_ECDSA_SHA3_512);
    } // method static

    ECDSA(P11CryptService cryptService, P11IdentityId identityId,
        AlgorithmIdentifier signatureAlgId, boolean plain)
        throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, signatureAlgId);

      this.plain = plain;

      String algOid = signatureAlgId.getAlgorithm().getId();
      HashAlgo hashAlgo = sigAlgHashMap.get(algOid);
      if (hashAlgo == null) {
        throw new XiSecurityException("unsupported signature algorithm " + algOid);
      }

      P11Slot slot = cryptService.getSlot(identityId.getSlotId());

      long mech = hashMechMap.get(hashAlgo).longValue();
      if (slot.supportsMechanism(mech)) {
        mechanism = mech;
        this.outputStream = new ByteArrayOutputStream();
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_ECDSA)) {
        mechanism = PKCS11Constants.CKM_ECDSA;
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + algOid);
      }
    } // method constructor

    @Override
    public OutputStream getOutputStream() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
      }
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      try {
        byte[] plainSignature = getPlainSignature();
        return plain ? plainSignature : SignerUtil.dsaSigPlainToX962(plainSignature);
      } catch (XiSecurityException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("XiSecurityException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

    private byte[] getPlainSignature() throws XiSecurityException, P11TokenException {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
      }

      return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
    }
  } // method ECDSA

  // CHECKSTYLE:SKIP
  static class EdDSA extends P11ContentSigner {

    private final ByteArrayOutputStream outputStream;

    private final long mechanism;

    EdDSA(P11CryptService cryptService, P11IdentityId identityId,
        AlgorithmIdentifier signatureAlgId)
        throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, signatureAlgId);

      ASN1ObjectIdentifier algOid = signatureAlgId.getAlgorithm();
      if (!EdECConstants.id_ED25519.equals(algOid)) {
        throw new XiSecurityException("unsupproted signature algorithm " + algOid.getId());
      }

      mechanism = PKCS11Constants.CKM_EDDSA;

      P11Slot slot = cryptService.getSlot(identityId.getSlotId());
      if (slot.supportsMechanism(mechanism)) {
        throw new XiSecurityException("unsupported signature algorithm " + algOid.getId());
      }

      this.outputStream = new ByteArrayOutputStream();
    }

    @Override
    public OutputStream getOutputStream() {
      outputStream.reset();
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      byte[] content = outputStream.toByteArray();
      outputStream.reset();
      try {
        return cryptService.getIdentity(identityId).sign(mechanism, null, content);
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

  } // class EdDSA

  static class Mac extends P11ContentSigner {

    private final long mechanism;

    private final ByteArrayOutputStream outputStream;

    Mac(P11CryptService cryptService, P11IdentityId identityId,
        AlgorithmIdentifier macAlgId) throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, macAlgId);

      ASN1ObjectIdentifier oid = macAlgId.getAlgorithm();
      if (PKCSObjectIdentifiers.id_hmacWithSHA1.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA_1_HMAC;
      } else if (PKCSObjectIdentifiers.id_hmacWithSHA224.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA224_HMAC;
      } else if (PKCSObjectIdentifiers.id_hmacWithSHA256.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA256_HMAC;
      } else if (PKCSObjectIdentifiers.id_hmacWithSHA384.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA384_HMAC;
      } else if (PKCSObjectIdentifiers.id_hmacWithSHA512.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA512_HMAC;
      } else if (NISTObjectIdentifiers.id_hmacWithSHA3_224.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA3_224_HMAC;
      } else if (NISTObjectIdentifiers.id_hmacWithSHA3_256.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA3_256_HMAC;
      } else if (NISTObjectIdentifiers.id_hmacWithSHA3_384.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA3_384_HMAC;
      } else if (NISTObjectIdentifiers.id_hmacWithSHA3_512.equals(oid)) {
        mechanism = PKCS11Constants.CKM_SHA3_512_HMAC;
      } else {
        throw new IllegalArgumentException("unknown algorithm identifier " + oid.getId());
      }

      P11Slot slot = cryptService.getSlot(identityId.getSlotId());
      if (slot.supportsMechanism(mechanism)) {
        throw new XiSecurityException("unsupported MAC algorithm " + oid.getId());
      }

      this.outputStream = new ByteArrayOutputStream();
    } // constructor

    @Override
    public OutputStream getOutputStream() {
      outputStream.reset();
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      try {
        byte[] dataToSign = outputStream.toByteArray();
        outputStream.reset();
        return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
      } catch (P11TokenException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("P11TokenException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

  } // class Mac

  // CHECKSTYLE:SKIP
  static class RSA extends P11ContentSigner {

    private static final Map<ASN1ObjectIdentifier, HashAlgo> sigAlgHashAlgMap = new HashMap<>();

    private static final Map<HashAlgo, Long> hashAlgMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    private final byte[] digestPkcsPrefix;

    private final int modulusBitLen;

    static {
      sigAlgHashAlgMap.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, HashAlgo.SHA1);
      sigAlgHashAlgMap.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, HashAlgo.SHA224);
      sigAlgHashAlgMap.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, HashAlgo.SHA256);
      sigAlgHashAlgMap.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, HashAlgo.SHA384);
      sigAlgHashAlgMap.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, HashAlgo.SHA512);
      sigAlgHashAlgMap.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224,
          HashAlgo.SHA3_224);
      sigAlgHashAlgMap.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256,
          HashAlgo.SHA3_256);
      sigAlgHashAlgMap.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384,
          HashAlgo.SHA3_384);
      sigAlgHashAlgMap.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512,
          HashAlgo.SHA3_512);

      hashAlgMechMap.put(HashAlgo.SHA1, PKCS11Constants.CKM_SHA1_RSA_PKCS);
      hashAlgMechMap.put(HashAlgo.SHA224, PKCS11Constants.CKM_SHA224_RSA_PKCS);
      hashAlgMechMap.put(HashAlgo.SHA256, PKCS11Constants.CKM_SHA256_RSA_PKCS);
      hashAlgMechMap.put(HashAlgo.SHA384, PKCS11Constants.CKM_SHA384_RSA_PKCS);
      hashAlgMechMap.put(HashAlgo.SHA512, PKCS11Constants.CKM_SHA512_RSA_PKCS);
      hashAlgMechMap.put(HashAlgo.SHA3_224, PKCS11Constants.CKM_SHA3_224_RSA_PKCS);
      hashAlgMechMap.put(HashAlgo.SHA3_256, PKCS11Constants.CKM_SHA3_256_RSA_PKCS);
      hashAlgMechMap.put(HashAlgo.SHA3_384, PKCS11Constants.CKM_SHA3_384_RSA_PKCS);
      hashAlgMechMap.put(HashAlgo.SHA3_512, PKCS11Constants.CKM_SHA3_512_RSA_PKCS);
    } // method static

    RSA(P11CryptService cryptService, P11IdentityId identityId,
        AlgorithmIdentifier signatureAlgId) throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, signatureAlgId);

      ASN1ObjectIdentifier algOid = signatureAlgId.getAlgorithm();
      HashAlgo hashAlgo = sigAlgHashAlgMap.get(algOid);
      if (hashAlgo == null) {
        throw new XiSecurityException("unsupported signature algorithm " + algOid.getId());
      }

      P11SlotIdentifier slotId = identityId.getSlotId();
      P11Slot slot = cryptService.getSlot(slotId);

      long mech = hashAlgMechMap.get(hashAlgo).longValue();
      if (slot.supportsMechanism(mech)) {
        mechanism = mech;
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_PKCS)) {
        mechanism = PKCS11Constants.CKM_RSA_PKCS;
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_X_509)) {
        mechanism = PKCS11Constants.CKM_RSA_X_509;
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + algOid.getId());
      }

      if (mechanism == PKCS11Constants.CKM_RSA_PKCS || mechanism == PKCS11Constants.CKM_RSA_X_509) {
        this.digestPkcsPrefix = SignerUtil.getDigestPkcsPrefix(hashAlgo);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else {
        this.digestPkcsPrefix = null;
        this.outputStream = new ByteArrayOutputStream();
      }

      RSAPublicKey rsaPubKey = (RSAPublicKey) cryptService.getIdentity(identityId).getPublicKey();
      this.modulusBitLen = rsaPubKey.getModulus().bitLength();
    } // constructor

    @Override
    public OutputStream getOutputStream() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
      }
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        byte[] hashValue = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
        dataToSign = new byte[digestPkcsPrefix.length + hashValue.length];
        System.arraycopy(digestPkcsPrefix, 0, dataToSign, 0, digestPkcsPrefix.length);
        System.arraycopy(hashValue, 0, dataToSign, digestPkcsPrefix.length, hashValue.length);
      }

      try {
        if (mechanism == PKCS11Constants.CKM_RSA_X_509) {
          dataToSign = SignerUtil.EMSA_PKCS1_v1_5_encoding(dataToSign, modulusBitLen);
        }

        return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
      } catch (XiSecurityException | P11TokenException ex) {
        LogUtil.error(LOG, ex, "could not sign");
        throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
      }
    } // method getSignature

  } // class RSA

  // CHECKSTYLE:SKIP
  static class RSAPSS extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashAlgMechMap = new HashMap<>();

    static {
      hashAlgMechMap.put(HashAlgo.SHA1, PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS);
      hashAlgMechMap.put(HashAlgo.SHA224, PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS);
      hashAlgMechMap.put(HashAlgo.SHA256, PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS);
      hashAlgMechMap.put(HashAlgo.SHA384, PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS);
      hashAlgMechMap.put(HashAlgo.SHA512, PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS);
      hashAlgMechMap.put(HashAlgo.SHA3_224, PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS);
      hashAlgMechMap.put(HashAlgo.SHA3_256, PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS);
      hashAlgMechMap.put(HashAlgo.SHA3_384, PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS);
      hashAlgMechMap.put(HashAlgo.SHA3_512, PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS);
    } // method static

    // CHECKSTYLE:SKIP
    private static class PSSSignerOutputStream extends OutputStream {

      private PSSSigner pssSigner;

      PSSSignerOutputStream(PSSSigner pssSigner) {
        this.pssSigner = pssSigner;
      }

      @Override
      public void write(int oneByte) throws IOException {
        pssSigner.update((byte) oneByte);
      }

      @Override
      public void write(byte[] bytes) throws IOException {
        pssSigner.update(bytes, 0, bytes.length);
      }

      @Override
      public void write(byte[] bytes, int off, int len) throws IOException {
        pssSigner.update(bytes, off, len);
      }

      public void reset() {
        pssSigner.reset();
      }

      @Override
      public void flush() throws IOException {
      }

      @Override
      public void close() throws IOException {
      }

      byte[] generateSignature() throws DataLengthException, CryptoException {
        byte[] signature = pssSigner.generateSignature();
        pssSigner.reset();
        return signature;
      }

    } // class PSSSignerOutputStream

    private final long mechanism;

    private final P11Params.P11RSAPkcsPssParams parameters;

    private final OutputStream outputStream;

    RSAPSS(P11CryptService cryptService, P11IdentityId identityId,
        AlgorithmIdentifier signatureAlgId, SecureRandom random)
        throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, signatureAlgId);
      notNull(random, "random");

      ASN1ObjectIdentifier sigOid = signatureAlgId.getAlgorithm();
      if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigOid)) {
        throw new XiSecurityException("unsupported signature algorithm "
            + signatureAlgId.getAlgorithm());
      }

      RSASSAPSSparams asn1Params = RSASSAPSSparams.getInstance(signatureAlgId.getParameters());
      ASN1ObjectIdentifier digestAlgOid = asn1Params.getHashAlgorithm().getAlgorithm();
      HashAlgo hashAlgo = HashAlgo.getInstance(digestAlgOid);
      if (hashAlgo == null) {
        throw new XiSecurityException("unsupported hash algorithm " + digestAlgOid.getId());
      }

      P11SlotIdentifier slotId = identityId.getSlotId();
      P11Slot slot = cryptService.getSlot(slotId);

      long mech = hashAlgMechMap.get(hashAlgo).longValue();
      if (slot.supportsMechanism(mech)) {
        this.mechanism = mech;
        this.parameters = new P11Params.P11RSAPkcsPssParams(asn1Params);
        this.outputStream = new ByteArrayOutputStream();
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_PKCS_PSS)) {
        this.mechanism = PKCS11Constants.CKM_RSA_PKCS_PSS;
        this.parameters = new P11Params.P11RSAPkcsPssParams(asn1Params);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_X_509)) {
        this.mechanism = PKCS11Constants.CKM_RSA_X_509;
        this.parameters = null;
        AsymmetricBlockCipher cipher = new P11PlainRSASigner();
        P11RSAKeyParameter keyParam;
        try {
          keyParam = P11RSAKeyParameter.getInstance(cryptService, identityId);
        } catch (InvalidKeyException ex) {
          throw new XiSecurityException(ex.getMessage(), ex);
        }
        PSSSigner pssSigner = SignerUtil.createPSSRSASigner(signatureAlgId, cipher);
        pssSigner.init(true, new ParametersWithRandom(keyParam, random));
        this.outputStream = new PSSSignerOutputStream(pssSigner);
      } else {
        throw new XiSecurityException("unsupported signature algorithm "
            + sigOid.getId() + " with " + hashAlgo);
      }
    } // constructor

    @Override
    public OutputStream getOutputStream() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else if (outputStream instanceof DigestOutputStream) {
        ((DigestOutputStream) outputStream).reset();
      } else {
        ((PSSSignerOutputStream) outputStream).reset();
      }

      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      if (outputStream instanceof PSSSignerOutputStream) {
        try {
          return ((PSSSignerOutputStream) outputStream).generateSignature();
        } catch (CryptoException ex) {
          LogUtil.warn(LOG, ex);
          throw new RuntimeCryptoException("CryptoException: " + ex.getMessage());
        }
      }

      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
      }

      try {
        return cryptService.getIdentity(identityId).sign(mechanism, parameters, dataToSign);
      } catch (P11TokenException ex) {
        LogUtil.warn(LOG, ex, "could not sign");
        throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
      }

    } // method getSignature

  } // class RSAPSS

  static class SM2 extends P11ContentSigner {

    private static final Map<String, HashAlgo> sigAlgHashMap = new HashMap<>();

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    // CHECKSTYLE:SKIP
    private final byte[] z;

    static {
      sigAlgHashMap.put(GMObjectIdentifiers.sm2sign_with_sm3.getId(), HashAlgo.SM3);
      hashMechMap.put(HashAlgo.SM3, PKCS11Constants.CKM_VENDOR_SM2_SM3);
    }

    SM2(P11CryptService cryptService, P11IdentityId identityId,
        AlgorithmIdentifier signatureAlgId, ASN1ObjectIdentifier curveOid, BigInteger pubPointX,
        BigInteger pubPointY) throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, signatureAlgId);

      String algOid = signatureAlgId.getAlgorithm().getId();
      HashAlgo hashAlgo = sigAlgHashMap.get(algOid);
      if (hashAlgo == null) {
        throw new XiSecurityException("unsupported signature algorithm " + algOid);
      }

      P11Slot slot = cryptService.getSlot(identityId.getSlotId());

      long mech = hashMechMap.get(hashAlgo);
      if (slot.supportsMechanism(mech)) {
        this.mechanism = mech;
        this.z = null; // not required
        this.outputStream = new ByteArrayOutputStream();
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_VENDOR_SM2)) {
        this.mechanism = PKCS11Constants.CKM_VENDOR_SM2;
        this.z = GMUtil.getSM2Z(curveOid, pubPointX, pubPointY);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + algOid);
      }
    }

    @Override
    public OutputStream getOutputStream() {
      reset();
      return outputStream;
    }

    private void reset() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
        try {
          outputStream.write(z, 0, z.length);
        } catch (IOException ex) {
          throw new IllegalStateException(ex.getMessage());
        }
      }
    }

    @Override
    public byte[] getSignature() {
      try {
        byte[] plainSignature = getPlainSignature();
        return SignerUtil.dsaSigPlainToX962(plainSignature);
      } catch (XiSecurityException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("XiSecurityException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

    private byte[] getPlainSignature() throws XiSecurityException, P11TokenException {
      byte[] dataToSign;
      P11Params.P11ByteArrayParams params;
      if (outputStream instanceof ByteArrayOutputStream) {
        // dataToSign is the real message
        params = new P11Params.P11ByteArrayParams(GMUtil.getDefaultIDA());
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
      } else {
        // dataToSign is Hash(Z||Real Message)
        params = null;
        dataToSign = ((DigestOutputStream) outputStream).digest();
      }

      reset();

      return cryptService.getIdentity(identityId).sign(mechanism, params, dataToSign);
    }
  } // class SM2

}
