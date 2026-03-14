// #THIRDPARTY copyright BouncyCastle, License MIT-style.

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

/**
 * PKCS#12 keystore implementation for loading and storing key material.
 */
public class PKCS12KeyStore implements PKCSObjectIdentifiers, NISTObjectIdentifiers {

  private static final KeyIvSizeProvider sizeProvider = new KeyIvSizeProvider();

  private static final int SALT_SIZE = 20;
  private static final int MIN_ITERATIONS = 1024;

  private IgnoresCaseHashtable<PrivateKeyInfo> keys = new IgnoresCaseHashtable<>();
  private IgnoresCaseHashtable<String> localIds = new IgnoresCaseHashtable<>();
  private IgnoresCaseHashtable<Certificate> certs = new IgnoresCaseHashtable<>();
  private Hashtable<CertId, Certificate> chainCerts = new Hashtable<>();
  private Hashtable<String, Certificate> keyCerts = new Hashtable<>();

  private boolean wrongPKCS12Zero = false;

  protected final SecureRandom random;

  // use of final causes problems with JDK 1.2 compiler
  private final ASN1ObjectIdentifier keyAlgorithm;
  private final ASN1ObjectIdentifier certAlgorithm;

  public PKCS12KeyStore() {
    this(pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC, new SecureRandom());
  }

  public PKCS12KeyStore(
      ASN1ObjectIdentifier keyAlgorithm, ASN1ObjectIdentifier certAlgorithm, SecureRandom random) {
    this.keyAlgorithm = keyAlgorithm;
    this.certAlgorithm = certAlgorithm;
    this.random = random;
  }

  private static SubjectKeyIdentifier createSubjectKeyId(SubjectPublicKeyInfo pubKey) {
    return new SubjectKeyIdentifier(getDigest(pubKey));
  }

  private static byte[] getDigest(SubjectPublicKeyInfo spki) {
    return HashAlgo.SHA1.hash(Asn1Util.getPublicKeyData(spki));
  }

  public Enumeration<String> aliases() {
    Hashtable<String, String> tab = new Hashtable<>();

    Enumeration<String> e = certs.keys();
    while (e.hasMoreElements()) {
      tab.put(e.nextElement(), "cert");
    }

    e = keys.keys();
    while (e.hasMoreElements()) {
      String a = e.nextElement();
      tab.putIfAbsent(a, "key");
    }

    return tab.keys();
  }

  public boolean containsAlias(String alias) {
    Args.notNull(alias, "alias");

    return (certs.get(alias) != null || keys.get(alias) != null);
  }

  /**
   * this is not quite complete - we should follow up on the chain, a bit
   * tricky if a certificate appears in more than one chain so we rely on
   * the storage method to prune out orphaned chain certificates that we no
   * longer use.
   */
  public void deleteEntry(String alias) throws KeyStoreException {
    Key k = (Key) keys.remove(alias);
    Certificate c = certs.remove(alias);
    if (c != null) {
      removeChainCert(c);
    }

    if (k != null) {
      String id = localIds.remove(alias);
      if (id != null) {
        c = keyCerts.remove(id);
      }

      if (c != null) {
        removeChainCert(c);
      }
    }
  }

  private void removeChainCert(Certificate c) {
    chainCerts.remove(new CertId(c.getSubjectPublicKeyInfo()));
  }

  /**
   * simply return the cert for the private key
   */
  public Certificate getCertificate(String alias) {
    Args.notNull(alias, "alias");

    Certificate c = certs.get(alias);

    // look up the key table - and try the local key id
    if (c == null) {
      String id = localIds.get(alias);
      return keyCerts.get(id != null ? id : alias);
    }

    return c;
  }

  public String getCertificateAlias(Certificate cert) {
    Enumeration<Certificate> c = certs.elements();
    Enumeration<String> k = certs.keys();

    while (c.hasMoreElements()) {
      Certificate tc = c.nextElement();
      String ta = k.nextElement();
      if (tc.equals(cert)) {
        return ta;
      }
    }

    c = keyCerts.elements();
    k = keyCerts.keys();

    while (c.hasMoreElements()) {
      Certificate tc = c.nextElement();
      String ta = k.nextElement();

      if (tc.equals(cert)) {
        return ta;
      }
    }

    return null;
  }

  public Certificate[] getCertificateChain(String alias) {
    Args.notNull(alias, "alias");

    if (!isKeyEntry(alias)) {
      return null;
    }

    Certificate c = getCertificate(alias);

    if (c != null) {
      Vector<Certificate> cs = new Vector<>();
      while (c != null) {
        Certificate nextC = null;

        ASN1Encodable extnValue = c.getTBSCertificate().getExtensions()
            .getExtensionParsedValue(Extension.authorityKeyIdentifier);
        if (extnValue != null) {
          AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extnValue);

          byte[] keyID = Asn1Util.getKeyIdentifier(aki);
          if (null != keyID) {
            nextC = chainCerts.get(new CertId(keyID));
          }
        }

        if (nextC == null) {
          // no authority key id, try the Issuer DN
          X500Name i = c.getIssuer();
          X500Name s = c.getSubject();

          if (!i.equals(s)) {
            Enumeration<CertId> e = chainCerts.keys();

            while (e.hasMoreElements()) {
              Certificate crt = chainCerts.get(e.nextElement());
              X500Name sub = crt.getSubject();
              if (sub.equals(i)) {
                nextC = crt;
                break;
              }
            }
          }
        }

        if (cs.contains(c)) {
          c = null;         // we've got a loop - stop now.
        } else {
          cs.addElement(c);
          if (nextC != c) {  // self-signed - end of the chain
            c = nextC;
          } else {
            c = null;
          }
        }
      }

      Certificate[] certChain = new Certificate[cs.size()];

      for (int i = 0; i != certChain.length; i++) {
        certChain[i] = cs.elementAt(i);
      }

      return certChain;
    }

    return null;
  }

  public Date getCreationDate(String alias) {
    Args.notNull(alias, "alias");

    if (keys.get(alias) == null && certs.get(alias) == null) {
      return null;
    }
    return new Date();
  }

  public PrivateKeyInfo getKey(String alias) {
    Args.notNull(alias, "alias");

    return keys.get(alias);
  }

  public boolean isCertificateEntry(String alias) {
    return (certs.get(alias) != null && keys.get(alias) == null);
  }

  public boolean isKeyEntry(String alias) {
    return (keys.get(alias) != null);
  }

  public void setCertificateEntry(String alias, Certificate cert)
      throws KeyStoreException {
    if (keys.get(alias) != null) {
      throw new KeyStoreException("There is a key entry with the name " + alias + ".");
    }

    certs.put(alias, cert);
    putChainCert(cert);
  }

  public void setKeyEntry(String alias, PrivateKeyInfo key, Certificate cert)
      throws KeyStoreException {
    Args.notNull(cert, "cert");
    setKeyEntry(alias, key, new Certificate[] {cert});
  }

  public void setKeyEntry(String alias, PrivateKeyInfo key, Certificate[] chain)
      throws KeyStoreException {
    if (key == null) {
      throw new KeyStoreException("PKCS12 does not support null key");
    }

    int numCerts = 0;
    for (Certificate cert : chain) {
      if (cert != null) {
        numCerts++;
      }
    }

    if (numCerts == 0) {
      throw new KeyStoreException("no certificate chain for private key");
    }

    if (keys.get(alias) != null) {
      deleteEntry(alias);
    }

    keys.put(alias, key);
    certs.put(alias, chain[0]);

    for (int i = 0; i != chain.length; i++) {
      putChainCert(chain[i]);
    }
  }

  private void putChainCert(Certificate c) {
    chainCerts.put(new CertId(c.getSubjectPublicKeyInfo()), c);
  }

  protected PrivateKeyInfo unwrapKey(AlgorithmIdentifier algId, byte[] data, char[] password)
      throws IOException {
    ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
    try {
      Cipher cipher;
      if (algorithm.on(pkcs_12PbeIds)) {
        cipher = createPKCS12Cipher(Cipher.UNWRAP_MODE, password, algId);
      } else if (algorithm.equals(id_PBES2)) {
        cipher = createPBES2Cipher(Cipher.UNWRAP_MODE, password, algId);
      } else {
        throw new IOException("exception unwrapping private key - cannot recognize: " + algorithm);
      }

      // we pass "" as the key algorithm type as it is unknown at this point
      byte[] bytes = cipher.unwrap(data, "", Cipher.SECRET_KEY).getEncoded();
      return PrivateKeyInfo.getInstance(bytes);
    } catch (IOException e) {
      throw e;
    } catch (final Exception e) {
      throw new IOException("exception unwrapping private key - " + e.getMessage(), e);
    }
  }

  protected byte[] wrapKey(AlgorithmIdentifier algId, PrivateKeyInfo key, char[] password)
      throws IOException {
    ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
    try {
      Cipher cipher;
      if (algorithm.on(pkcs_12PbeIds)) {
        cipher = createPKCS12Cipher(Cipher.WRAP_MODE, password, algId);
      } else if (algorithm.equals(id_PBES2)) {
        cipher = createPBES2Cipher(Cipher.WRAP_MODE, password, algId);
      } else {
        throw new IOException("exception unwrapping private key - cannot recognize: " + algorithm);
      }

      // we pass "" as the key algorithm type as it is unknown at this point
      return cipher.wrap(new SecretKeySpec(key.getEncoded(), ""));
    } catch (IOException e) {
      throw e;
    } catch (final Exception e) {
      throw new IOException("exception unwrapping private key - " + e.getMessage(), e);
    }
  }

  protected byte[] cryptData(
      boolean forEncryption, AlgorithmIdentifier algId, char[] password, byte[] data)
      throws IOException {
    ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
    int mode = (forEncryption) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

    try {
      Cipher cipher;
      if (algorithm.on(pkcs_12PbeIds)) {
        cipher = createPKCS12Cipher(mode, password, algId);
      } else if (algorithm.equals(id_PBES2)) {
        cipher = createPBES2Cipher(mode, password, algId);
      } else {
        throw new IOException("unknown PBE algorithm: " + algorithm);
      }

      return cipher.doFinal(data);
    } catch (IOException e) {
      throw e;
    } catch (final Exception e) {
      throw new IOException("exception decrypting data - " + e.getMessage(), e);
    }
  }

  private Cipher createPKCS12Cipher(int mode, char[] password, AlgorithmIdentifier algId)
      throws NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidKeyException, NoSuchProviderException {
    PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
    PKCS12KeyWithParameters key = new PKCS12KeyWithParameters(password,
        wrongPKCS12Zero, pbeParams.getIV(), pbeParams.getIterations().intValue());

    Cipher cipher = Cipher.getInstance(algId.getAlgorithm().getId(), KeyUtil.tradProviderName());
    cipher.init(mode, key, random);
    return cipher;
  }

  private Cipher createPBES2Cipher(int mode, char[] password, AlgorithmIdentifier algId)
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
    PBES2Parameters alg = PBES2Parameters.getInstance(algId.getParameters());
    PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
    AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

    SecretKeyFactory keyFact = SecretKeyFactory.getInstance(
        alg.getKeyDerivationFunc().getAlgorithm().getId(), KeyUtil.tradProviderName());
    SecretKey key;

    if (func.isDefaultPrf()) {
      key = keyFact.generateSecret(new PBEKeySpec(password, func.getSalt(),
          func.getIterationCount().intValue(), sizeProvider.getKeySize(encScheme) * 8));
    } else {
      key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(),
          func.getIterationCount().intValue(), sizeProvider.getKeySize(encScheme) * 8,
          func.getPrf()));
    }

    Cipher cipher = Cipher.getInstance(encScheme.getAlgorithm().getId(),
        KeyUtil.tradProviderName());

    ASN1Encodable encParams = encScheme.getParameters();
    AlgorithmParameterSpec params;
    if (encParams instanceof ASN1OctetString) {
      params = new IvParameterSpec(Asn1Util.getOctetStringOctets(encParams));
    } else {
      // TODO: at the moment it's just GOST, but...
      GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);
      params = new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV());
    }
    cipher.init(mode, key, params, random);
    return cipher;
  }

  public void load(InputStream stream, char[] password) throws IOException {
    if (stream == null) {
      // just initialising
      return;
    }

    if (password == null) {
      throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
    }

    BufferedInputStream bufIn = new BufferedInputStream(stream);
    bufIn.mark(10);

    int head = bufIn.read();
    if (head < 0) {
      throw new EOFException("no data in keystore stream");
    }

    if (head != 0x30) {
      throw new IOException("stream does not represent a PKCS12 key store");
    }

    bufIn.reset();

    ASN1InputStream bIn = new ASN1InputStream(bufIn);
    ASN1Sequence obj = (ASN1Sequence) bIn.readObject();
    Pfx bag = Pfx.getInstance(obj);
    ContentInfo info = bag.getAuthSafe();
    Vector<SafeBag> chain = new Vector<>();
    boolean unmarkedKey = false;

    if (bag.getMacData() != null) { // check the mac code
      MacData mData = bag.getMacData();
      DigestInfo dInfo = mData.getMac();
      AlgorithmIdentifier algId = dInfo.getAlgorithmId();
      byte[] salt = mData.getSalt();
      int itCount = mData.getIterationCount().intValue();

      byte[] data = Asn1Util.getOctetStringOctets(info.getContent());

      try {
        byte[] res = calculatePbeMac(algId, salt, itCount, password, data);
        byte[] dig = dInfo.getDigest();

        if (!Arrays.constantTimeAreEqual(res, dig)) {
          if (password.length > 0) {
            throw new IOException(
                "PKCS12 key store mac invalid - wrong password or corrupted file.");
          }

          // Try with incorrect zero length password
          res = calculatePbeMacWrongZero(algId, salt, itCount, data);

          if (!Arrays.constantTimeAreEqual(res, dig)) {
            throw new IOException(
                "PKCS12 key store mac invalid - wrong password or corrupted file.");
          }

          wrongPKCS12Zero = true;
        }
      } catch (IOException e) {
        throw e;
      } catch (final Exception e) {
        throw new IOException("error constructing MAC: " + e.getMessage(), e);
      }
    }

    keys = new IgnoresCaseHashtable<>();
    localIds = new IgnoresCaseHashtable<>();

    if (info.getContentType().equals(data)) {
      bIn = new ASN1InputStream(Asn1Util.getOctetStringOctets(info.getContent()));

      AuthenticatedSafe authSafe = AuthenticatedSafe.getInstance(bIn.readObject());
      ContentInfo[] c = authSafe.getContentInfo();

      for (int i = 0; i != c.length; i++) {
        ASN1ObjectIdentifier ciType = c[i].getContentType();
        ASN1Encodable ciContent = c[i].getContent();

        if (ciType.equals(data)) {
          ASN1InputStream dIn = new ASN1InputStream(Asn1Util.getOctetStringOctets(ciContent));
          ASN1Sequence seq = (ASN1Sequence) dIn.readObject();

          for (int j = 0; j != seq.size(); j++) {
            SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));
            if (b.getBagId().equals(pkcs8ShroudedKeyBag)) {
              EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.getInstance(b.getBagValue());
              PrivateKeyInfo privKey = unwrapKey(eIn.getEncryptionAlgorithm(),
                                        eIn.getEncryptedData(), password);

              // set the attributes on the key
              String alias = null;
              ASN1OctetString localId = null;

              if (b.getBagAttributes() != null) {
                Enumeration<?> e = b.getBagAttributes().getObjects();
                while (e.hasMoreElements()) {
                  ASN1Sequence sq = (ASN1Sequence) e.nextElement();
                  ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier) sq.getObjectAt(0);
                  ASN1Set attrSet = (ASN1Set) sq.getObjectAt(1);
                  ASN1Primitive attr;
                  if (attrSet.size() > 0) {
                    attr = (ASN1Primitive) attrSet.getObjectAt(0);

                    if (aOid.equals(pkcs_9_at_friendlyName)) {
                      alias = getAlias(alias, attr);
                      keys.put(alias, privKey);
                    } else if (aOid.equals(pkcs_9_at_localKeyId)) {
                      localId = getLocalId(localId, attr);
                    }
                  }
                }
              }

              if (localId != null) {
                String name = Strings.fromByteArray(Hex.encode(localId.getOctets()));

                if (alias == null) {
                  keys.put(name, privKey);
                } else {
                  localIds.put(alias, name);
                }
              } else {
                unmarkedKey = true;
                keys.put("unmarked", privKey);
              }
            } else if (b.getBagId().equals(certBag)) {
              chain.addElement(b);
            } else {
              //LOG.info("extra in data " + b.getBagId());
            }
          }
        } else if (ciType.equals(encryptedData)) {
          EncryptedData d = EncryptedData.getInstance(ciContent);
          byte[] octets = cryptData(false, d.getEncryptionAlgorithm(),
              password, d.getContent().getOctets());
          ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(octets);

          for (int j = 0; j != seq.size(); j++) {
            SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));

            if (b.getBagId().equals(certBag)) {
              chain.addElement(b);
            } else if (b.getBagId().equals(pkcs8ShroudedKeyBag)) {
              EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.getInstance(b.getBagValue());
              PrivateKeyInfo privKey = unwrapKey(eIn.getEncryptionAlgorithm(),
                                          eIn.getEncryptedData(), password);
              String alias = null;
              ASN1OctetString localId = null;

              Enumeration<?> e = b.getBagAttributes().getObjects();
              while (e.hasMoreElements()) {
                ASN1Sequence sq = (ASN1Sequence) e.nextElement();
                ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier) sq.getObjectAt(0);
                ASN1Set attrSet = (ASN1Set) sq.getObjectAt(1);
                ASN1Primitive attr;
                if (attrSet.size() > 0) {
                  attr = (ASN1Primitive) attrSet.getObjectAt(0);

                  if (aOid.equals(pkcs_9_at_friendlyName)) {
                    alias = getAlias(alias, attr);
                    keys.put(alias, privKey);
                  } else if (aOid.equals(pkcs_9_at_localKeyId)) {
                    localId = getLocalId(localId, attr);
                  }
                }
              }

              String name = Strings.fromByteArray(Hex.encode(localId.getOctets()));

              if (alias == null) {
                keys.put(name, privKey);
              } else {
                localIds.put(alias, name);
              }
            } else if (b.getBagId().equals(keyBag)) {
              PrivateKeyInfo privKey = PrivateKeyInfo.getInstance(b.getBagValue());

              String alias = null;
              ASN1OctetString localId = null;

              Enumeration<?> e = b.getBagAttributes().getObjects();
              while (e.hasMoreElements()) {
                ASN1Sequence sq = (ASN1Sequence) e.nextElement();
                ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier) sq.getObjectAt(0);
                ASN1Set attrSet = (ASN1Set) sq.getObjectAt(1);
                ASN1Primitive attr;
                if (attrSet.size() > 0) {
                  attr = (ASN1Primitive) attrSet.getObjectAt(0);

                  if (aOid.equals(pkcs_9_at_friendlyName)) {
                    alias = getAlias(alias, attr);
                    keys.put(alias, privKey);
                  } else if (aOid.equals(pkcs_9_at_localKeyId)) {
                    localId = getLocalId(localId, attr);
                  }
                }
              }

              if (localId != null) {
                String name = Strings.fromByteArray(Hex.encode(localId.getOctets()));
                if (alias == null) {
                  keys.put(name, privKey);
                } else {
                  localIds.put(alias, name);
                }
              }
            } else {
              //LOG.info("extra in encryptedData {}", b.getBagId());
            }
          }
        } else {
          //LOG.info("extra {}", c[i].getContentType().getId());
        }
      }
    }

    certs = new IgnoresCaseHashtable<>();
    chainCerts = new Hashtable<>();
    keyCerts   = new Hashtable<>();

    for (int i = 0; i != chain.size(); i++) {
      SafeBag b = chain.elementAt(i);
      CertBag cb = CertBag.getInstance(b.getBagValue());

      if (!cb.getCertId().equals(x509Certificate)) {
        throw new IOException("Unsupported certificate type: " + cb.getCertId());
      }

      Certificate cert;
      try {
        byte[] cIn = ((ASN1OctetString) cb.getCertValue()).getOctets();
        cert = Certificate.getInstance(cIn);
      } catch (final Exception e) {
        throw new IOException(e.toString(), e);
      }

      // set the attributes
      ASN1OctetString localId = null;
      String alias = null;

      if (b.getBagAttributes() != null) {
        Enumeration<?> e = b.getBagAttributes().getObjects();
        while (e.hasMoreElements()) {
          ASN1Sequence sq = (ASN1Sequence) e.nextElement();
          ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) sq.getObjectAt(0);
          ASN1Primitive attr = (ASN1Primitive) ((ASN1Set) sq.getObjectAt(1)).getObjectAt(0);

          if (oid.equals(pkcs_9_at_friendlyName)) {
            alias = getAlias(alias, attr);
          } else if (oid.equals(pkcs_9_at_localKeyId)) {
            localId = getLocalId(localId, attr);
          }
        }
      }

      chainCerts.put(new CertId(cert.getSubjectPublicKeyInfo()), cert);

      if (unmarkedKey) {
        if (keyCerts.isEmpty()) {
          String name = Strings.fromByteArray(Hex.encode(
                  createSubjectKeyId(cert.getSubjectPublicKeyInfo()).getKeyIdentifier()));

          keyCerts.put(name, cert);
          keys.put(name, keys.remove("unmarked"));
        }
      } else {
        // the local key id needs to override the friendly name
        if (localId != null) {
          String name = Strings.fromByteArray(Hex.encode(localId.getOctets()));
          keyCerts.put(name, cert);
        }

        if (alias != null) {
          certs.put(alias, cert);
        }
      }
    }
  }

  public void store(OutputStream stream, char[] password) throws IOException {
    Args.notNull(password, "password");

    // handle the key
    ASN1EncodableVector keyS = new ASN1EncodableVector();

    Enumeration<?> ks = keys.keys();
    while (ks.hasMoreElements()) {
      byte[] kSalt = new byte[SALT_SIZE];
      random.nextBytes(kSalt);
      String name = (String) ks.nextElement();
      PrivateKeyInfo privKey = keys.get(name);
      PKCS12PBEParams kParams = new PKCS12PBEParams(kSalt, MIN_ITERATIONS);
      AlgorithmIdentifier kAlgId = new AlgorithmIdentifier(keyAlgorithm, kParams);
      byte[] kBytes = wrapKey(kAlgId, privKey, password);

      EncryptedPrivateKeyInfo kInfo = new EncryptedPrivateKeyInfo(kAlgId, kBytes);
      ASN1EncodableVector kName = new ASN1EncodableVector();

      // set a default friendly name (from the key id) and local id
      ASN1EncodableVector kSeq = new ASN1EncodableVector();
      Certificate ct = getCertificate(name);

      kSeq.add(pkcs_9_at_localKeyId);
      kSeq.add(new DERSet(createSubjectKeyId(ct.getSubjectPublicKeyInfo())));
      kName.add(new DERSequence(kSeq));

      kSeq = new ASN1EncodableVector();
      kSeq.add(pkcs_9_at_friendlyName);
      kSeq.add(new DERSet(new DERBMPString(name)));

      kName.add(new DERSequence(kSeq));

      SafeBag kBag = new SafeBag(pkcs8ShroudedKeyBag, kInfo.toASN1Primitive(), new DERSet(kName));
      keyS.add(kBag);
    }

    byte[] keySEncoded = new DERSequence(keyS).getEncoded(ASN1Encoding.DER);
    BEROctetString keyString = new BEROctetString(keySEncoded);

    // certificate processing
    byte[] cSalt = new byte[SALT_SIZE];
    random.nextBytes(cSalt);

    ASN1EncodableVector certSeq = new ASN1EncodableVector();
    PKCS12PBEParams cParams = new PKCS12PBEParams(cSalt, MIN_ITERATIONS);
    AlgorithmIdentifier cAlgId = new AlgorithmIdentifier(certAlgorithm, cParams.toASN1Primitive());
    Hashtable<Certificate, Certificate> doneCerts = new Hashtable<>();

    Enumeration<String> cs = keys.keys();
    while (cs.hasMoreElements()) {
      try {
        String name = cs.nextElement();
        Certificate cert = getCertificate(name);
        CertBag cBag = new CertBag(x509Certificate, new DEROctetString(cert.getEncoded()));
        ASN1EncodableVector fName = new ASN1EncodableVector();
        ASN1EncodableVector fSeq = new ASN1EncodableVector();

        fSeq.add(pkcs_9_at_localKeyId);
        fSeq.add(new DERSet(createSubjectKeyId(cert.getSubjectPublicKeyInfo())));
        fName.add(new DERSequence(fSeq));

        fSeq = new ASN1EncodableVector();
        fSeq.add(pkcs_9_at_friendlyName);
        fSeq.add(new DERSet(new DERBMPString(name)));

        fName.add(new DERSequence(fSeq));

        SafeBag sBag = new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));

        certSeq.add(sBag);

        doneCerts.put(cert, cert);
      } catch (Exception e) {
        throw new IOException("Error encoding certificate: " + e);
      }
    }

    cs = certs.keys();
    while (cs.hasMoreElements()) {
      try {
        String certId = cs.nextElement();
        Certificate cert = certs.get(certId);
        if (keys.get(certId) != null) {
          continue;
        }

        CertBag cBag = new CertBag(x509Certificate, new DEROctetString(cert.getEncoded()));
        ASN1EncodableVector fName = new ASN1EncodableVector();
        ASN1EncodableVector fSeq = new ASN1EncodableVector();

        fSeq.add(pkcs_9_at_friendlyName);
        fSeq.add(new DERSet(new DERBMPString(certId)));

        fName.add(new DERSequence(fSeq));

        TBSCertificate tbsCert = cert.getTBSCertificate();
        Extensions exts = tbsCert.getExtensions();
        if (exts != null) {
          Extension extUsage = exts.getExtension(Extension.extendedKeyUsage);
          if (extUsage != null) {
            fSeq = new ASN1EncodableVector();

            // oracle trusted key usage OID.
            fSeq.add(MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage);
            fSeq.add(new DERSet(
                    ExtendedKeyUsage.getInstance(extUsage.getParsedValue()).getUsages()));
            fName.add(new DERSequence(fSeq));
          } else {
            fSeq = new ASN1EncodableVector();

            fSeq.add(MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage);
            fSeq.add(new DERSet(KeyPurposeId.anyExtendedKeyUsage));
            fName.add(new DERSequence(fSeq));
          }
        } else {
          fSeq = new ASN1EncodableVector();
          fSeq.add(MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage);
          fSeq.add(new DERSet(KeyPurposeId.anyExtendedKeyUsage));
          fName.add(new DERSequence(fSeq));
        }

        SafeBag sBag = new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));
        certSeq.add(sBag);
        doneCerts.put(cert, cert);
      } catch (RuntimeException e) {
        throw new IOException("Error encoding certificate: " + e);
      }
    }

    Set<Certificate> usedSet = getUsedCertificateSet();

    Enumeration<CertId> cs2 = chainCerts.keys();
    while (cs2.hasMoreElements()) {
      try {
        CertId certId = cs2.nextElement();
        Certificate cert = chainCerts.get(certId);

        if (!usedSet.contains(cert)) {
          continue;
        }

        if (doneCerts.get(cert) != null) {
          continue;
        }

        CertBag cBag = new CertBag(x509Certificate, new DEROctetString(cert.getEncoded()));
        ASN1EncodableVector fName = new ASN1EncodableVector();

        SafeBag sBag = new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));

        certSeq.add(sBag);
      } catch (Exception e) {
        throw new IOException("Error encoding certificate: " + e);
      }
    }

    byte[] certSeqEncoded = new DERSequence(certSeq).getEncoded(ASN1Encoding.DER);
    byte[] certBytes = cryptData(true, cAlgId, password, certSeqEncoded);
    EncryptedData cInfo = new EncryptedData(data, cAlgId, new BEROctetString(certBytes));

    ContentInfo[] info = new ContentInfo[]{new ContentInfo(data, keyString),
        new ContentInfo(encryptedData, cInfo.toASN1Primitive())};

    AuthenticatedSafe auth = new AuthenticatedSafe(info);
    byte[] pkg = auth.getEncoded(ASN1Encoding.DER);

    ContentInfo mainInfo = new ContentInfo(data, new BEROctetString(pkg));

    // create the mac
    byte[] mSalt = new byte[20];
    int itCount = MIN_ITERATIONS;

    random.nextBytes(mSalt);

    byte[] data = ((ASN1OctetString) mainInfo.getContent()).getOctets();

    MacData mData;
    try {
      AlgorithmIdentifier algId = new AlgorithmIdentifier(
          X509ObjectIdentifiers.id_SHA1, DERNull.INSTANCE);
      byte[] res = calculatePbeMac(algId, mSalt, itCount, password, data);
      DigestInfo dInfo = new DigestInfo(algId, res);
      mData = new MacData(dInfo, mSalt, itCount);
    } catch (Exception e) {
      throw new IOException("error constructing MAC: " + e.getMessage());
    }

    // output the Pfx
    Pfx pfx = new Pfx(mainInfo, mData);
    stream.write(pfx.getEncoded(ASN1Encoding.DER));
  }

  private byte[] calculatePbeMacWrongZero(
      AlgorithmIdentifier algID, byte[] salt, int itCount, byte[] data) throws Exception {
    return KeyUtil.p12CalculatePbeMac(algID, salt, itCount, new char[0], true, data);
  }

  private byte[] calculatePbeMac(
      AlgorithmIdentifier algID, byte[] salt, int itCount, char[] password, byte[] data)
      throws Exception {
    return KeyUtil.p12CalculatePbeMac(algID, salt, itCount, password, false, data);
  }

  private static class CertId {
    private final byte[] id;

    private CertId(SubjectPublicKeyInfo key) {
      this.id = createSubjectKeyId(key).getKeyIdentifier();
    }

    private CertId(byte[] id) {
      this.id = id;
    }

    public int hashCode() {
      return Arrays.hashCode(id);
    }

    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }

      if (!(o instanceof CertId)) {
        return false;
      }

      CertId cId = (CertId) o;
      return Arrays.areEqual(id, cId.id);
    }
  }

  private static class IgnoresCaseHashtable<V> {
    private final Hashtable<String, V> orig = new Hashtable<>();
    private final Hashtable<String, String> keys = new Hashtable<>();

    public void put(String key, V value) {
      String lower = Strings.toLowerCase(key);
      String k = keys.get(lower);
      if (k != null) {
        orig.remove(k);
      }

      keys.put(lower, key);
      orig.put(key, value);
    }

    public Enumeration<String> keys() {
      return orig.keys();
    }

    public V remove(String alias) {
      if (alias == null) {
        return null;
      }

      String k = keys.remove(Strings.toLowerCase(alias));
      if (k == null) {
        return null;
      }

      return orig.remove(k);
    }

    public V get(String alias) {
      if (alias == null) {
        return null;
      }

      String k = keys.get(Strings.toLowerCase(alias));
      if (k == null) {
        return null;
      }

      return orig.get(k);
    }

    public Enumeration<V> elements() {
      return orig.elements();
    }

    public void clear() {
      orig.clear();
    }
  } // class IgnoresCaseHashtable

  private Set<Certificate> getUsedCertificateSet() {
    Set<Certificate> usedSet = new HashSet<>();

    for (Enumeration<String> en = keys.keys(); en.hasMoreElements(); ) {
      String alias = en.nextElement();
      Certificate[] certs = getCertificateChain(alias);
      usedSet.addAll(java.util.Arrays.asList(certs));
    }

    for (Enumeration<String> en = certs.keys(); en.hasMoreElements(); ) {
      String alias = en.nextElement();
      Certificate cert = getCertificate(alias);
      usedSet.add(cert);
    }

    return usedSet;
  }

  private static String getAlias(String alias, ASN1Primitive attr) throws IOException {
    String newAlias = Asn1Util.getBMPString(attr);
    if (alias != null && !alias.equals(newAlias)) {
      throw new IOException("attempt to add existing attribute with different value");
    }
    return newAlias;
  }

  private static ASN1OctetString getLocalId(
      ASN1OctetString localId, ASN1Primitive attr) throws IOException {
    if (localId != null && !localId.equals(attr)) {
      throw new IOException("attempt to add existing attribute with different value");
    }
    return ASN1OctetString.getInstance(attr);
  }

  private static class KeyIvSizeProvider {
    private final Map<String, Integer> KEY_SIZES;

    KeyIvSizeProvider() {
      Map<String, Integer> keySizes = new HashMap<>();

      keySizes.put(MiscObjectIdentifiers.cast5CBC.getId(), 16);

      keySizes.put(des_EDE3_CBC.getId(), 24);
      keySizes.put(id_alg_CMS3DESwrap.getId(), 24);
      keySizes.put(des_EDE3_CBC.getId(), 24);

      keySizes.put(id_aes128_CBC.getId(), 16);
      keySizes.put(id_aes192_CBC.getId(), 24);
      keySizes.put(id_aes256_CBC.getId(), 32);
      keySizes.put(id_aes128_GCM.getId(), 16);
      keySizes.put(id_aes192_GCM.getId(), 24);
      keySizes.put(id_aes256_GCM.getId(), 32);
      keySizes.put(id_aes128_CCM.getId(), 16);
      keySizes.put(id_aes192_CCM.getId(), 24);
      keySizes.put(id_aes256_CCM.getId(), 32);
      keySizes.put(id_aes128_CFB.getId(), 16);
      keySizes.put(id_aes192_CFB.getId(), 24);
      keySizes.put(id_aes256_CFB.getId(), 32);
      keySizes.put(id_aes128_OFB.getId(), 16);
      keySizes.put(id_aes192_OFB.getId(), 24);
      keySizes.put(id_aes256_OFB.getId(), 32);
      keySizes.put(id_aes128_wrap.getId(), 16);
      keySizes.put(id_aes192_wrap.getId(), 24);
      keySizes.put(id_aes256_wrap.getId(), 32);

      keySizes.put(id_hmacWithSHA1.getId(), 20);
      keySizes.put(id_hmacWithSHA224.getId(), 28);
      keySizes.put(id_hmacWithSHA256.getId(), 32);
      keySizes.put(id_hmacWithSHA384.getId(), 48);
      keySizes.put(id_hmacWithSHA512.getId(), 64);

      keySizes.put(NTTObjectIdentifiers.id_camellia128_cbc.getId(), 16);
      keySizes.put(NTTObjectIdentifiers.id_camellia192_cbc.getId(), 24);
      keySizes.put(NTTObjectIdentifiers.id_camellia256_cbc.getId(), 32);
      keySizes.put(NTTObjectIdentifiers.id_camellia128_wrap.getId(), 16);
      keySizes.put(NTTObjectIdentifiers.id_camellia192_wrap.getId(), 24);
      keySizes.put(NTTObjectIdentifiers.id_camellia256_wrap.getId(), 32);

      keySizes.put(KISAObjectIdentifiers.id_seedCBC.getId(), 16);
      keySizes.put(KISAObjectIdentifiers.id_seedMAC.getId(), 16);
      keySizes.put(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId(), 16);

      keySizes.put(OIWObjectIdentifiers.desCBC.getId(), 8);

      keySizes.put(CryptoProObjectIdentifiers.gostR28147_gcfb.getId(), 32);
      keySizes.put(CryptoProObjectIdentifiers.gostR3411Hmac.getId(), 32);

      keySizes.put(pbeWithSHAAnd2_KeyTripleDES_CBC.getId(), 16);
      keySizes.put(pbeWithSHAAnd3_KeyTripleDES_CBC.getId(), 24);
      keySizes.put(pbeWithSHAAnd128BitRC2_CBC.getId(), 16);
      keySizes.put(pbeWithSHAAnd128BitRC4.getId(), 16);
      keySizes.put(pbeWithSHAAnd40BitRC2_CBC.getId(), 5);

      KEY_SIZES = Collections.unmodifiableMap(keySizes);
    }

    public int getKeySize(AlgorithmIdentifier algId) {
      Integer keySize = KEY_SIZES.get(algId.getAlgorithm().getId());
      if (keySize != null) {
        return keySize;
      }

      return -1;
    }
  }
}
