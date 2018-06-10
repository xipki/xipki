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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
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
//CHECKSTYLE:SKIP
class P11ECDSAContentSigner implements XiContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(P11ECDSAContentSigner.class);

  private static final Map<String, HashAlgo> sigAlgHashMap = new HashMap<>();

  private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

  private final P11CryptService cryptService;

  private final P11EntityIdentifier identityId;

  private final AlgorithmIdentifier algorithmIdentifier;

  private final byte[] encodedAlgorithmIdentifier;

  private final long mechanism;

  private final OutputStream outputStream;

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
  }

  P11ECDSAContentSigner(P11CryptService cryptService, P11EntityIdentifier identityId,
      AlgorithmIdentifier signatureAlgId, boolean plain)
      throws XiSecurityException, P11TokenException {
    this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
    this.identityId = ParamUtil.requireNonNull("identityId", identityId);
    this.algorithmIdentifier = ParamUtil.requireNonNull("signatureAlgId", signatureAlgId);
    try {
      this.encodedAlgorithmIdentifier = algorithmIdentifier.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
    this.plain = plain;

    String algOid = signatureAlgId.getAlgorithm().getId();
    HashAlgo hashAlgo = sigAlgHashMap.get(algOid);
    if (hashAlgo == null) {
      throw new XiSecurityException("unsupported signature algorithm " + algOid);
    }

    P11Slot slot = cryptService.getSlot(identityId.getSlotId());
    if (slot.supportsMechanism(PKCS11Constants.CKM_ECDSA)) {
      this.mechanism = PKCS11Constants.CKM_ECDSA;
      Digest digest = hashAlgo.createDigest();
      this.outputStream = new DigestOutputStream(digest);
    } else {
      this.mechanism = hashMechMap.get(hashAlgo).longValue();
      if (!slot.supportsMechanism(this.mechanism)) {
        throw new XiSecurityException("unsupported signature algorithm " + algOid);
      }
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
}
