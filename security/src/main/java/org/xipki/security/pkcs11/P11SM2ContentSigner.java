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
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.exception.P11TokenException;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.Args;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
//CHECKSTYLE:SKIP
class P11SM2ContentSigner implements XiContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(P11SM2ContentSigner.class);

  private static final Map<String, HashAlgo> sigAlgHashMap = new HashMap<>();

  private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

  private final P11CryptService cryptService;

  private final P11IdentityId identityId;

  private final AlgorithmIdentifier algorithmIdentifier;

  private final byte[] encodedAlgorithmIdentifier;

  private final long mechanism;

  private final OutputStream outputStream;

  // CHECKSTYLE:SKIP
  private final byte[] z;

  static {
    sigAlgHashMap.put(GMObjectIdentifiers.sm2sign_with_sm3.getId(), HashAlgo.SM3);
    hashMechMap.put(HashAlgo.SM3, PKCS11Constants.CKM_VENDOR_SM2_SM3);
  }

  P11SM2ContentSigner(P11CryptService cryptService, P11IdentityId identityId,
      AlgorithmIdentifier signatureAlgId, ASN1ObjectIdentifier curveOid, BigInteger pubPointX,
      BigInteger pubPointY) throws XiSecurityException, P11TokenException {
    this.cryptService = Args.notNull(cryptService, "cryptService");
    this.identityId = Args.notNull(identityId, "identityId");
    this.algorithmIdentifier = Args.notNull(signatureAlgId, "signatureAlgId");
    try {
      this.encodedAlgorithmIdentifier = algorithmIdentifier.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    String algOid = signatureAlgId.getAlgorithm().getId();
    HashAlgo hashAlgo = sigAlgHashMap.get(algOid);
    if (hashAlgo == null) {
      throw new XiSecurityException("unsupported signature algorithm " + algOid);
    }

    P11Slot slot = cryptService.getSlot(identityId.getSlotId());
    if (slot.supportsMechanism(PKCS11Constants.CKM_VENDOR_SM2)) {
      this.z = GMUtil.getSM2Z(curveOid, pubPointX, pubPointY);

      this.mechanism = PKCS11Constants.CKM_VENDOR_SM2;
      Digest digest = hashAlgo.createDigest();
      this.outputStream = new DigestOutputStream(digest);
    } else {
      this.z = null; // not required

      Long ll = hashMechMap.get(hashAlgo);
      if (ll == null) {
        throw new XiSecurityException("hash algorithm " + hashAlgo + " is not suitable for SM2");
      }
      this.mechanism = ll.longValue();
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
    P11ByteArrayParams params;
    if (outputStream instanceof ByteArrayOutputStream) {
      // dataToSign is the real message
      params = new P11ByteArrayParams(GMUtil.getDefaultIDA());
      dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
    } else {
      // dataToSign is Hash(Z||Real Message)
      params = null;
      dataToSign = ((DigestOutputStream) outputStream).digest();
    }

    reset();

    return cryptService.getIdentity(identityId).sign(mechanism, params, dataToSign);
  }
}
