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
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.exception.P11TokenException;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
//CHECKSTYLE:SKIP
class P11RSAContentSigner implements XiContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(P11RSAContentSigner.class);

  private static final Map<ASN1ObjectIdentifier, HashAlgo> sigAlgHashAlgMap = new HashMap<>();

  private static final Map<HashAlgo, Long> hashAlgMecMap = new HashMap<>();

  private final AlgorithmIdentifier algorithmIdentifier;

  private final byte[] encodedAlgorithmIdentifier;

  private final long mechanism;

  private final OutputStream outputStream;

  private final P11CryptService cryptService;

  private final P11IdentityId identityId;

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

    hashAlgMecMap.put(HashAlgo.SHA1, PKCS11Constants.CKM_SHA1_RSA_PKCS);
    hashAlgMecMap.put(HashAlgo.SHA224, PKCS11Constants.CKM_SHA224_RSA_PKCS);
    hashAlgMecMap.put(HashAlgo.SHA256, PKCS11Constants.CKM_SHA256_RSA_PKCS);
    hashAlgMecMap.put(HashAlgo.SHA384, PKCS11Constants.CKM_SHA384_RSA_PKCS);
    hashAlgMecMap.put(HashAlgo.SHA512, PKCS11Constants.CKM_SHA512_RSA_PKCS);
    hashAlgMecMap.put(HashAlgo.SHA3_224, PKCS11Constants.CKM_SHA3_224_RSA_PKCS);
    hashAlgMecMap.put(HashAlgo.SHA3_256, PKCS11Constants.CKM_SHA3_256_RSA_PKCS);
    hashAlgMecMap.put(HashAlgo.SHA3_384, PKCS11Constants.CKM_SHA3_384_RSA_PKCS);
    hashAlgMecMap.put(HashAlgo.SHA3_512, PKCS11Constants.CKM_SHA3_512_RSA_PKCS);
  }

  P11RSAContentSigner(P11CryptService cryptService, P11IdentityId identityId,
      AlgorithmIdentifier signatureAlgId) throws XiSecurityException, P11TokenException {
    this.cryptService = Args.notNull(cryptService, "cryptService");
    this.identityId = Args.notNull(identityId, "identityId");
    this.algorithmIdentifier = Args.notNull(signatureAlgId, "signatureAlgId");
    try {
      this.encodedAlgorithmIdentifier = algorithmIdentifier.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    ASN1ObjectIdentifier algOid = signatureAlgId.getAlgorithm();
    HashAlgo hashAlgo = sigAlgHashAlgMap.get(algOid);
    if (hashAlgo == null) {
      throw new XiSecurityException("unsupported signature algorithm " + algOid.getId());
    }

    P11SlotIdentifier slotId = identityId.getSlotId();
    P11Slot slot = cryptService.getSlot(slotId);
    if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_PKCS)) {
      this.mechanism = PKCS11Constants.CKM_RSA_PKCS;
    } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_X_509)) {
      this.mechanism = PKCS11Constants.CKM_RSA_X_509;
    } else {
      Long mech = hashAlgMecMap.get(hashAlgo);
      if (mech == null) {
        throw new IllegalStateException("should not reach here, unknown HashAlgo " + hashAlgo);
      }
      this.mechanism = mech.longValue();
      if (!slot.supportsMechanism(this.mechanism)) {
        throw new XiSecurityException("unsupported signature algorithm " + algOid.getId());
      }
    }

    if (mechanism == PKCS11Constants.CKM_RSA_PKCS || mechanism == PKCS11Constants.CKM_RSA_X_509) {
      this.digestPkcsPrefix = SignerUtil.getDigestPkcsPrefix(hashAlgo);
      Digest digest = hashAlgo.createDigest();
      this.outputStream = new DigestOutputStream(digest);
    } else {
      this.digestPkcsPrefix = null;
      this.outputStream = new ByteArrayOutputStream();
    }

    RSAPublicKey rsaPubKey = (RSAPublicKey) cryptService.getIdentity(identityId).getPublicKey();
    this.modulusBitLen = rsaPubKey.getModulus().bitLength();
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
  }

}
