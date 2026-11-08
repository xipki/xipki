// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cms;

import org.xipki.asn1.cms.ecc.EccCmsSharedInfo;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.crypto.GCMParameters;
import org.xipki.codec.util.XiArrays;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.RSAESOAEPParams;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.OiwOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.asn1.oid.SecOIDs;
import org.xipki.codec.asn1.oid.X9OIDs;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.util.exception.PkixException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * The cryptographic operations of CMS, implemented with the JCA of {@link CryptoApi}.
 *
 * @author Lijun Liao (xipki)
 */
final class CmsCrypto {

  private static final CryptoApi crypto = CryptoApiFactory.get();

  /**
   * Content encryption algorithms: OID to {cipher name, key size in bits, IV size in bytes}.
   */
  private static final Map<Asn1Oid, Object[]> CONTENT_ALGS = new HashMap<>();

  private static final Set<Asn1Oid> GCM_ALGS = Set.of(
      NistOIDs.id_aes128_GCM, NistOIDs.id_aes192_GCM, NistOIDs.id_aes256_GCM);

  /**
   * Key wrap algorithms: OID to key size in bits.
   */
  private static final Map<Asn1Oid, Integer> WRAP_KEY_SIZES = new HashMap<>();

  /**
   * ECDH with X9.63 KDF (RFC 5753): OID to the digest name of the KDF. Standard and cofactor
   * ECDH are identical for the supported curves (cofactor 1).
   */
  private static final Map<Asn1Oid, String> ECDH_KDF_ALGS = new HashMap<>();

  /**
   * Digest algorithm to the PKCS#1 v1.5 RSA signature algorithm.
   */
  private static final Map<Asn1Oid, Asn1Oid> RSA_SIG_ALGS = new HashMap<>();

  static {
    CONTENT_ALGS.put(PkcsOIDs.des_EDE3_CBC,   new Object[]{"DESede/CBC/PKCS5Padding", 192, 8});
    CONTENT_ALGS.put(NistOIDs.id_aes128_CBC,  new Object[]{"AES/CBC/PKCS5Padding", 128, 16});
    CONTENT_ALGS.put(NistOIDs.id_aes192_CBC,  new Object[]{"AES/CBC/PKCS5Padding", 192, 16});
    CONTENT_ALGS.put(NistOIDs.id_aes256_CBC,  new Object[]{"AES/CBC/PKCS5Padding", 256, 16});
    CONTENT_ALGS.put(NistOIDs.id_aes128_GCM,  new Object[]{"AES/GCM/NoPadding", 128, 12});
    CONTENT_ALGS.put(NistOIDs.id_aes192_GCM,  new Object[]{"AES/GCM/NoPadding", 192, 12});
    CONTENT_ALGS.put(NistOIDs.id_aes256_GCM,  new Object[]{"AES/GCM/NoPadding", 256, 12});

    WRAP_KEY_SIZES.put(NistOIDs.id_aes128_wrap, 128);
    WRAP_KEY_SIZES.put(NistOIDs.id_aes192_wrap, 192);
    WRAP_KEY_SIZES.put(NistOIDs.id_aes256_wrap, 256);

    ECDH_KDF_ALGS.put(X9OIDs.dhSinglePass_stdDH_sha1kdf_scheme,        "SHA-1");
    ECDH_KDF_ALGS.put(SecOIDs.dhSinglePass_stdDH_sha224kdf_scheme,     "SHA-224");
    ECDH_KDF_ALGS.put(SecOIDs.dhSinglePass_stdDH_sha256kdf_scheme,     "SHA-256");
    ECDH_KDF_ALGS.put(SecOIDs.dhSinglePass_stdDH_sha384kdf_scheme,     "SHA-384");
    ECDH_KDF_ALGS.put(SecOIDs.dhSinglePass_stdDH_sha512kdf_scheme,     "SHA-512");
    ECDH_KDF_ALGS.put(X9OIDs.dhSinglePass_cofactorDH_sha1kdf_scheme,    "SHA-1");
    ECDH_KDF_ALGS.put(SecOIDs.dhSinglePass_cofactorDH_sha224kdf_scheme, "SHA-224");
    ECDH_KDF_ALGS.put(SecOIDs.dhSinglePass_cofactorDH_sha256kdf_scheme, "SHA-256");
    ECDH_KDF_ALGS.put(SecOIDs.dhSinglePass_cofactorDH_sha384kdf_scheme, "SHA-384");
    ECDH_KDF_ALGS.put(SecOIDs.dhSinglePass_cofactorDH_sha512kdf_scheme, "SHA-512");

    RSA_SIG_ALGS.put(OiwOIDs.idSHA1,       PkcsOIDs.sha1WithRSAEncryption);
    RSA_SIG_ALGS.put(NistOIDs.id_sha224,   PkcsOIDs.sha224WithRSAEncryption);
    RSA_SIG_ALGS.put(NistOIDs.id_sha256,   PkcsOIDs.sha256WithRSAEncryption);
    RSA_SIG_ALGS.put(NistOIDs.id_sha384,   PkcsOIDs.sha384WithRSAEncryption);
    RSA_SIG_ALGS.put(NistOIDs.id_sha512,   PkcsOIDs.sha512WithRSAEncryption);
    RSA_SIG_ALGS.put(NistOIDs.id_sha3_224, NistOIDs.id_rsassa_pkcs1_v1_5_with_sha3_224);
    RSA_SIG_ALGS.put(NistOIDs.id_sha3_256, NistOIDs.id_rsassa_pkcs1_v1_5_with_sha3_256);
    RSA_SIG_ALGS.put(NistOIDs.id_sha3_384, NistOIDs.id_rsassa_pkcs1_v1_5_with_sha3_384);
    RSA_SIG_ALGS.put(NistOIDs.id_sha3_512, NistOIDs.id_rsassa_pkcs1_v1_5_with_sha3_512);
  }

  /**
   * The encrypted content and the content-encryption key.
   */
  static final class EncryptedContent {

    final AlgorithmIdentifier algorithm;

    final byte[] cek;

    final byte[] encryptedContent;

    private EncryptedContent(AlgorithmIdentifier algorithm, byte[] cek, byte[] encryptedContent) {
      this.algorithm = algorithm;
      this.cek = cek;
      this.encryptedContent = encryptedContent;
    }

  }

  private CmsCrypto() {
  }

  static SecureRandom random() {
    return crypto.getSecureRandom();
  }

  static PublicKey publicKey(SubjectPublicKeyInfo publicKeyInfo) throws PkixException {
    try {
      return crypto.getPublicKey(publicKeyInfo);
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new PkixException("invalid public key: " + e.getMessage(), e);
    }
  }

  // ---------------- digest and signature ----------------

  static byte[] digest(AlgorithmIdentifier digestAlg, byte[] data) throws PkixException {
    try {
      MessageDigest md = crypto.newMessageDigest(crypto.getDigestName(digestAlg));
      return md.digest(data);
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new PkixException("unsupported digest algorithm "
          + digestAlg.getAlgorithm().getId() + ": " + e.getMessage(), e);
    }
  }

  /**
   * In SignerInfo, the signature algorithm of PKCS#1 v1.5 RSA signature may be given as
   * rsaEncryption, combined with the digest algorithm. This method returns the signature
   * algorithm to verify the signature.
   */
  static AlgorithmIdentifier signatureAlgorithm(
      AlgorithmIdentifier digestAlg, AlgorithmIdentifier signatureAlg) throws PkixException {
    if (!PkcsOIDs.rsaEncryption.equals(signatureAlg.getAlgorithm())) {
      return signatureAlg;
    }

    Asn1Oid oid = RSA_SIG_ALGS.get(digestAlg.getAlgorithm());
    if (oid == null) {
      throw new PkixException("unsupported digest algorithm for rsaEncryption: "
          + digestAlg.getAlgorithm().getId());
    }
    return AlgorithmIdentifier.ofNullParams(oid);
  }

  /**
   * Returns the signature algorithm written in the SignerInfo. As in BouncyCastle, MD5 and
   * SHA-1 with RSA are written as rsaEncryption.
   */
  static AlgorithmIdentifier signerInfoSignatureAlgorithm(AlgorithmIdentifier signatureAlg) {
    Asn1Oid oid = signatureAlg.getAlgorithm();
    if (PkcsOIDs.md5WithRSAEncryption.equals(oid) || PkcsOIDs.sha1WithRSAEncryption.equals(oid)
        || OiwOIDs.md5WithRSA.equals(oid) || OiwOIDs.sha1WithRSA.equals(oid)) {
      return AlgorithmIdentifier.ofNullParams(PkcsOIDs.rsaEncryption);
    }
    return signatureAlg;
  }

  // ---------------- content encryption ----------------

  static EncryptedContent encryptContent(Asn1Oid encAlg, byte[] content)
      throws PkixException {
    Object[] params = contentAlgParams(encAlg);
    SecureRandom random = random();
    int keySize = (int) params[1];
    byte[] iv = new byte[(int) params[2]];
    random.nextBytes(iv);

    byte[] cek;
    if (PkcsOIDs.des_EDE3_CBC.equals(encAlg)) {
      try {
        KeyGenerator kg = crypto.newKeyGenerator("DESede");
        kg.init(168, random);
        cek = kg.generateKey().getEncoded();
      } catch (GeneralSecurityException e) {
        throw new PkixException("could not generate DESede key: " + e.getMessage(), e);
      }
    } else {
      cek = new byte[keySize / 8];
      random.nextBytes(cek);
    }

    boolean gcm = GCM_ALGS.contains(encAlg);
    AlgorithmIdentifier algId = gcm
        ? AlgorithmIdentifier.build(encAlg, new GCMParameters(iv, 16))
        : new AlgorithmIdentifier(encAlg, new Asn1OctetString(iv));

    try {
      Cipher cipher = crypto.newCipher((String) params[0]);
      cipher.init(Cipher.ENCRYPT_MODE, contentKey(encAlg, cek),
          gcm ? new GCMParameterSpec(128, iv) : new IvParameterSpec(iv), random);
      // for GCM, the authentication tag is appended to the ciphertext.
      return new EncryptedContent(algId, cek, cipher.doFinal(content));
    } catch (GeneralSecurityException e) {
      throw new PkixException("could not encrypt content: " + e.getMessage(), e);
    }
  }

  static byte[] decryptContent(AlgorithmIdentifier encAlgId, byte[] cek, byte[] encryptedContent)
      throws PkixException {
    Asn1Oid encAlg = encAlgId.getAlgorithm();
    Object[] params = contentAlgParams(encAlg);
    try {
      AlgorithmParameterSpec spec;
      if (GCM_ALGS.contains(encAlg)) {
        GCMParameters gcmParams = GCMParameters.fromAsn1(encAlgId.getParameters().asSequence());
        spec = new GCMParameterSpec(gcmParams.icvLen() * 8, gcmParams.nonce());
      } else {
        spec = new IvParameterSpec(encAlgId.getParameters().asOctetString().getOctets());
      }

      Cipher cipher = crypto.newCipher((String) params[0]);
      cipher.init(Cipher.DECRYPT_MODE, contentKey(encAlg, cek), spec);
      return cipher.doFinal(encryptedContent);
    } catch (GeneralSecurityException | CodecException | RuntimeException e) {
      throw new PkixException("could not decrypt content: " + e.getMessage(), e);
    }
  }

  private static Object[] contentAlgParams(Asn1Oid encAlg) throws PkixException {
    Object[] params = CONTENT_ALGS.get(encAlg);
    if (params == null) {
      throw new PkixException("unsupported content encryption algorithm " + encAlg.getId());
    }
    return params;
  }

  private static SecretKey contentKey(Asn1Oid encAlg, byte[] cek) {
    return new SecretKeySpec(cek, PkcsOIDs.des_EDE3_CBC.equals(encAlg) ? "DESede" : "AES");
  }

  // ---------------- key transport ----------------

  static byte[] keyTransEncrypt(AlgorithmIdentifier keyEncAlg, PublicKey publicKey,
                                byte[] cek) throws PkixException {
    try {
      Cipher cipher = keyTransCipher(Cipher.ENCRYPT_MODE, keyEncAlg, publicKey);
      return cipher.doFinal(cek);
    } catch (GeneralSecurityException | CodecException e) {
      throw new PkixException("could not encrypt the content-encryption key: "
          + e.getMessage(), e);
    }
  }

  static byte[] keyTransDecrypt(AlgorithmIdentifier keyEncAlg, PrivateKey privateKey,
                                byte[] encryptedKey) throws PkixException {
    try {
      Cipher cipher = keyTransCipher(Cipher.DECRYPT_MODE, keyEncAlg, privateKey);
      return cipher.doFinal(encryptedKey);
    } catch (GeneralSecurityException | CodecException e) {
      throw new PkixException("could not decrypt the content-encryption key: "
          + e.getMessage(), e);
    }
  }

  private static Cipher keyTransCipher(int mode, AlgorithmIdentifier keyEncAlg,
                                       Key key)
      throws GeneralSecurityException, CodecException {
    Asn1Oid oid = keyEncAlg.getAlgorithm();
    SecureRandom random = random();
    if (PkcsOIDs.rsaEncryption.equals(oid)) {
      Cipher cipher = crypto.newCipher("RSA/ECB/PKCS1Padding");
      cipher.init(mode, key, random);
      return cipher;
    } else if (PkcsOIDs.id_RSAES_OAEP.equals(oid)) {
      Asn1Primitive params = keyEncAlg.getParameters();
      RSAESOAEPParams oaep = (params == null || params instanceof Asn1Null)
          ? new RSAESOAEPParams() : RSAESOAEPParams.fromAsn1(params.asSequence());
      Cipher cipher = crypto.newCipher("RSA/ECB/OAEPPadding");
      cipher.init(mode, key, oaepSpec(oaep), random);
      return cipher;
    } else {
      throw new GeneralSecurityException("unsupported key encryption algorithm " + oid.getId());
    }
  }

  private static OAEPParameterSpec oaepSpec(RSAESOAEPParams oaep)
      throws GeneralSecurityException, CodecException {
    AlgorithmIdentifier mgf = oaep.getMaskGenAlgorithm();
    if (!PkcsOIDs.id_mgf1.equals(mgf.getAlgorithm())) {
      throw new GeneralSecurityException("unsupported MGF " + mgf.getAlgorithm().getId());
    }

    AlgorithmIdentifier mgfDigest = AlgorithmIdentifier.fromAsn1(mgf.getParameters().asSequence());

    AlgorithmIdentifier pSource = oaep.getPSourceAlgorithm();
    if (!PkcsOIDs.id_pSpecified.equals(pSource.getAlgorithm())) {
      throw new GeneralSecurityException("unsupported pSource " + pSource.getAlgorithm().getId());
    }
    Asn1Primitive pValue = pSource.getParameters();
    byte[] p = (pValue == null) ? new byte[0] : pValue.asOctetString().getOctets();

    return new OAEPParameterSpec(crypto.getDigestName(oaep.getHashAlgorithm()), "MGF1",
        new MGF1ParameterSpec(crypto.getDigestName(mgfDigest)), new PSource.PSpecified(p));
  }

  // ---------------- key agreement ----------------

  static boolean isEcdhKdf(Asn1Oid keyAgreeAlg) {
    return ECDH_KDF_ALGS.containsKey(keyAgreeAlg);
  }

  /**
   * Calculates the key-encryption key with ECDH and the X9.63 KDF (RFC 5753), and wraps or
   * unwraps the content-encryption key with it.
   */
  static byte[] keyAgreeWrap(
      int mode, Asn1Oid keyAgreeAlg, AlgorithmIdentifier wrapAlg, PrivateKey privateKey,
      PublicKey peerPublicKey, byte[] ukm, byte[] key) throws PkixException {
    if (!isEcdhKdf(keyAgreeAlg)) {
      throw new PkixException("unsupported key agreement algorithm " + keyAgreeAlg.getId());
    }

    Asn1Oid wrapOid = wrapAlg.getAlgorithm();
    Integer wrapKeySize = WRAP_KEY_SIZES.get(wrapOid);
    if (wrapKeySize == null) {
      throw new PkixException("unsupported key wrap algorithm " + wrapOid.getId());
    }

    // RFC 5753, section 7.2: ECC-CMS-SharedInfo, keySize in bits as 4-byte big-endian.
    byte[] suppPubInfo = {(byte) (wrapKeySize >> 24), (byte) (wrapKeySize >> 16),
        (byte) (wrapKeySize >> 8), (byte) (int) wrapKeySize};
    byte[] sharedInfo = new EccCmsSharedInfo(wrapAlg, ukm, suppPubInfo).getEncoded();

    try {
      KeyAgreement agreement = crypto.newKeyAgreement("ECDH");
      agreement.init(privateKey, random());
      agreement.doPhase(peerPublicKey, true);
      byte[] z = agreement.generateSecret();
      byte[] kekBytes = x963Kdf(ECDH_KDF_ALGS.get(keyAgreeAlg), z, sharedInfo, wrapKeySize / 8);
      XiArrays.clear(z);
      SecretKey kek = new SecretKeySpec(kekBytes, "AES");
      XiArrays.clear(kekBytes);

      Cipher cipher = crypto.newCipher(wrapOid.getId());
      if (mode == Cipher.WRAP_MODE) {
        cipher.init(Cipher.WRAP_MODE, kek, random());
        return cipher.wrap(new SecretKeySpec(key, "AES"));
      } else {
        cipher.init(Cipher.UNWRAP_MODE, kek);
        return cipher.unwrap(key, "AES", Cipher.SECRET_KEY).getEncoded();
      }
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new PkixException("key agreement failed: " + e.getMessage(), e);
    }
  }

  /**
   * ANSI X9.63 KDF (SEC 1, section 3.6.1), as used by RFC 5753.
   */
  static byte[] x963Kdf(String digestName, byte[] z, byte[] sharedInfo, int keyLength)
      throws GeneralSecurityException {
    MessageDigest md = crypto.newMessageDigest(digestName);
    byte[] out = new byte[keyLength];
    int off = 0;
    for (int counter = 1; off < keyLength; counter++) {
      md.update(z);
      md.update(new byte[]{(byte) (counter >> 24), (byte) (counter >> 16),
          (byte) (counter >> 8), (byte) counter});
      if (sharedInfo != null) {
        md.update(sharedInfo);
      }
      byte[] block = md.digest();
      int n = Math.min(block.length, keyLength - off);
      System.arraycopy(block, 0, out, off, n);
      off += n;
    }
    return out;
  }

  // ---------------- password ----------------

  /**
   * Returns the key size in bits of the key-encryption algorithm of the password recipient
   * (RFC 3211), or 0 if it is not supported.
   */
  static int passwordKekKeySize(Asn1Oid kekAlg) {
    if (GCM_ALGS.contains(kekAlg)) {
      return 0;
    }
    Object[] params = CONTENT_ALGS.get(kekAlg);
    return params == null ? 0 : (int) params[1];
  }

  static int passwordKekBlockSize(Asn1Oid kekAlg) {
    return PkcsOIDs.des_EDE3_CBC.equals(kekAlg) ? 8 : 16;
  }

  static byte[] pbkdf2(char[] password, PBKDF2Params params, int keySizeInBits)
      throws PkixException {
    try {
      return crypto.pbkdf2(params.getPrf(), password, params.salt(),
          params.iterationCount(), keySizeInBits / 8);
    } catch (GeneralSecurityException e) {
      throw new PkixException("could not derive key from password: " + e.getMessage(), e);
    }
  }

  /**
   * Wraps or unwraps the content-encryption key with the RFC 3211 key wrap.
   */
  static byte[] rfc3211Wrap(int mode, Asn1Oid kekAlg, byte[] kek, byte[] iv, byte[] key)
      throws PkixException {
    String keyAlg = PkcsOIDs.des_EDE3_CBC.equals(kekAlg) ? "DESede" : "AES";
    try {
      SecretKeySpec kekKey = new SecretKeySpec(kek, keyAlg);
      Cipher cipher = crypto.newCipher(keyAlg + "/CBC/NoPadding");
      int blockSize = cipher.getBlockSize();
      if (mode == Cipher.WRAP_MODE) {
        return rfc3211Wrap(cipher, blockSize, kekKey, iv, key);
      } else if (mode == Cipher.UNWRAP_MODE) {
        return rfc3211Unwrap(cipher, blockSize, kekKey, iv, key);
      } else {
        throw new IllegalArgumentException("invalid mode " + mode);
      }
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new PkixException("could not process the content-encryption key: "
          + e.getMessage(), e);
    }
  }

  // RFC 3211, section 2.3.1
  private static byte[] rfc3211Wrap(Cipher cipher, int blockSize, SecretKeySpec kek,
                                    byte[] iv, byte[] key) throws GeneralSecurityException {
    if (key.length > 255) {
      throw new GeneralSecurityException("key too long");
    }

    int len = 4 + key.length;
    int formattedLen = Math.max(2 * blockSize, ((len + blockSize - 1) / blockSize) * blockSize);
    byte[] formatted = new byte[formattedLen];
    formatted[0] = (byte) key.length;
    for (int i = 0; i < 3 && i < key.length; i++) {
      formatted[1 + i] = (byte) ~key[i];
    }
    System.arraycopy(key, 0, formatted, 4, key.length);
    if (formattedLen > len) {
      byte[] padding = new byte[formattedLen - len];
      random().nextBytes(padding);
      System.arraycopy(padding, 0, formatted, len, padding.length);
    }

    cipher.init(Cipher.ENCRYPT_MODE, kek, new IvParameterSpec(iv));
    byte[] c1 = cipher.doFinal(formatted);
    XiArrays.clear(formatted);

    byte[] iv2 = Arrays.copyOfRange(c1, c1.length - blockSize, c1.length);
    cipher.init(Cipher.ENCRYPT_MODE, kek, new IvParameterSpec(iv2));
    return cipher.doFinal(c1);
  }

  // RFC 3211, section 2.3.2
  private static byte[] rfc3211Unwrap(Cipher cipher, int blockSize, SecretKeySpec kek,
                                      byte[] iv, byte[] wrapped) throws GeneralSecurityException {
    int n = wrapped.length;
    if (n < 2 * blockSize || n % blockSize != 0) {
      throw new GeneralSecurityException("invalid wrapped key length");
    }

    // 1. decrypt the last block with the n-1'th block as IV
    byte[] ivLast = Arrays.copyOfRange(wrapped, n - 2 * blockSize, n - blockSize);
    cipher.init(Cipher.DECRYPT_MODE, kek, new IvParameterSpec(ivLast));
    byte[] lastInner = cipher.doFinal(wrapped, n - blockSize, blockSize);

    // 2. decrypt the first n-1 blocks with the recovered block as IV
    cipher.init(Cipher.DECRYPT_MODE, kek, new IvParameterSpec(lastInner));
    byte[] firstInner = cipher.doFinal(wrapped, 0, n - blockSize);

    byte[] inner = new byte[n];
    System.arraycopy(firstInner, 0, inner, 0, firstInner.length);
    System.arraycopy(lastInner, 0, inner, firstInner.length, blockSize);

    // 3. decrypt the inner layer with the original IV
    cipher.init(Cipher.DECRYPT_MODE, kek, new IvParameterSpec(iv));
    byte[] formatted = cipher.doFinal(inner);

    int keyLen = formatted[0] & 0xFF;
    if (keyLen < 3 || 4 + keyLen > formatted.length) {
      XiArrays.clear(formatted);
      throw new GeneralSecurityException("wrapped key corrupted");
    }

    int check = 0;
    for (int i = 0; i < 3; i++) {
      check |= ((byte) ~formatted[1 + i]) ^ formatted[4 + i];
    }

    if (check != 0) {
      XiArrays.clear(formatted);
      throw new GeneralSecurityException("wrapped key fails checksum");
    }

    byte[] key = Arrays.copyOfRange(formatted, 4, 4 + keyLen);
    XiArrays.clear(formatted);
    return key;
  }

}
