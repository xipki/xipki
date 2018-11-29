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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.exception.P11TokenException;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */
class P11MacContentSigner implements XiContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(P11MacContentSigner.class);

  private final P11CryptService cryptService;

  private final P11IdentityId identityId;

  private final AlgorithmIdentifier algorithmIdentifier;

  private final byte[] encodedAlgorithmIdentifier;

  private final long mechanism;

  private final ByteArrayOutputStream outputStream;

  P11MacContentSigner(P11CryptService cryptService, P11IdentityId identityId,
      AlgorithmIdentifier macAlgId) throws XiSecurityException, P11TokenException {
    this.identityId = Args.notNull(identityId, "identityId");
    this.cryptService = Args.notNull(cryptService, "cryptService");
    this.algorithmIdentifier = Args.notNull(macAlgId, "macAlgId");
    try {
      this.encodedAlgorithmIdentifier = algorithmIdentifier.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

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

    this.outputStream = new ByteArrayOutputStream();
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

}
