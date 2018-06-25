/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.exception.P11TokenException;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ParamUtil;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
class P11RSAPSSContentSigner implements XiContentSigner {

  private static final Map<HashAlgo, Long> hashAlgMecMap = new HashMap<>();

  static {
    hashAlgMecMap.put(HashAlgo.SHA1, PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS);
    hashAlgMecMap.put(HashAlgo.SHA224, PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS);
    hashAlgMecMap.put(HashAlgo.SHA256, PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS);
    hashAlgMecMap.put(HashAlgo.SHA384, PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS);
    hashAlgMecMap.put(HashAlgo.SHA512, PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS);
    hashAlgMecMap.put(HashAlgo.SHA3_224, PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS);
    hashAlgMecMap.put(HashAlgo.SHA3_256, PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS);
    hashAlgMecMap.put(HashAlgo.SHA3_384, PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS);
    hashAlgMecMap.put(HashAlgo.SHA3_512, PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS);
  }

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

  private static final Logger LOG = LoggerFactory.getLogger(P11RSAPSSContentSigner.class);

  private final AlgorithmIdentifier algorithmIdentifier;

  private final byte[] encodedAlgorithmIdentifier;

  private final P11CryptService cryptService;

  private final P11IdentityId identityId;

  private final long mechanism;

  private final P11RSAPkcsPssParams parameters;

  private final OutputStream outputStream;

  P11RSAPSSContentSigner(P11CryptService cryptService, P11IdentityId identityId,
      AlgorithmIdentifier signatureAlgId, SecureRandom random)
      throws XiSecurityException, P11TokenException {
    this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
    this.identityId = ParamUtil.requireNonNull("identityId", identityId);
    this.algorithmIdentifier = ParamUtil.requireNonNull("signatureAlgId", signatureAlgId);
    try {
      this.encodedAlgorithmIdentifier = algorithmIdentifier.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
    ParamUtil.requireNonNull("random", random);

    if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm())) {
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
    if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_PKCS_PSS)) {
      this.mechanism = PKCS11Constants.CKM_RSA_PKCS_PSS;
      this.parameters = new P11RSAPkcsPssParams(asn1Params);
      Digest digest = hashAlgo.createDigest();
      this.outputStream = new DigestOutputStream(digest);
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
      Long mech = hashAlgMecMap.get(hashAlgo);
      if (mech == null) {
        throw new RuntimeException("should not reach here, unknown HashAlgo " + hashAlgo);
      }
      this.mechanism = mech.longValue();
      if (!slot.supportsMechanism(this.mechanism)) {
        throw new XiSecurityException("unsupported signature algorithm "
            + PKCSObjectIdentifiers.id_RSASSA_PSS.getId() + " with " + hashAlgo);
      }
      this.parameters = new P11RSAPkcsPssParams(asn1Params);
      this.outputStream = new ByteArrayOutputStream();
    }
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algorithmIdentifier;
  }

  @Override
  public byte[] getEncodedAlgorithmIdentifier() {
    return Arrays.copyOf(encodedAlgorithmIdentifier, encodedAlgorithmIdentifier.length);
  }

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

  }

}
