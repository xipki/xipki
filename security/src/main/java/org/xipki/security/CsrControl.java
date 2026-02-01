// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.encap.KEMUtil;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.SecretKeyWithAlias;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.KeystoreConf;
import org.xipki.util.io.FileOrValue;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
public class CsrControl {

  private final SecretKeyWithAlias defaultKemMasterKey;

  private final Map<String, SecretKeyWithAlias> kemMasterKeys;

  private final List<X509Cert> peerCerts;

  public CsrControl() {
    this.defaultKemMasterKey = null;
    this.peerCerts = null;
    this.kemMasterKeys = Collections.emptyMap();
  }

  public CsrControl(CsrControlConf conf) throws InvalidConfException {
    if (conf.peerCerts() == null) {
      this.peerCerts = null;
    } else {
      try {
        peerCerts = X509Util.parseCerts(
            conf.peerCerts().readContent().getBytes(StandardCharsets.UTF_8));
      } catch (Exception e) {
        throw new InvalidConfException(e);
      }
    }

    this.kemMasterKeys = new HashMap<>();

    KeystoreConf kemConf = conf.kem();
    KeyStore ks;
    char[] password;

    try {
      password = Passwords.resolvePassword(kemConf.password());
    } catch (PasswordResolverException ex) {
      throw new InvalidConfException("error resolving password");
    }

    try (InputStream is = new ByteArrayInputStream(
        kemConf.keystore().readContent())) {
      ks = KeyUtil.getInKeyStore(kemConf.type());
      ks.load(is, password);
    } catch (GeneralSecurityException | IOException ex) {
      throw new InvalidConfException("error loading keystore", ex);
    }

    try {
      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (!ks.isKeyEntry(alias)) {
          continue;
        }

        Key key = ks.getKey(alias, password);
        if (key instanceof SecretKey) {
          // we consider only Secret key
          this.kemMasterKeys.put(alias,
              new SecretKeyWithAlias(alias, (SecretKey) key));
        }
      }
    } catch (GeneralSecurityException ex) {
      throw new InvalidConfException("invalid KEM pop configuration", ex);
    }

    if (this.kemMasterKeys.isEmpty()) {
      this.defaultKemMasterKey = null;
    } else {
      String alias = this.kemMasterKeys.keySet().iterator().next();
      this.defaultKemMasterKey = this.kemMasterKeys.get(alias);
    }
  }

  public List<X509Cert> peerCerts() {
    return peerCerts;
  }

  public KemEncapKey generateKemEncapKey(
      SubjectPublicKeyInfo publicKey, SecureRandom rnd)
      throws XiSecurityException {
    if (defaultKemMasterKey == null) {
      return null;
    }

    return KEMUtil.generateKemEncapKey(publicKey, defaultKemMasterKey, rnd);
  }

  public static class CsrControlConf {

    private FileOrValue peerCerts;

    private KeystoreConf kem;

    public FileOrValue peerCerts() {
      return peerCerts;
    }

    public void setPeerCerts(FileOrValue peerCerts) {
      this.peerCerts = peerCerts;
    }

    public KeystoreConf kem() {
      return kem;
    }

    public void setKem(KeystoreConf kem) {
      this.kem = kem;
    }

    public static CsrControlConf parse(JsonMap json) throws CodecException {
      CsrControlConf ret = new CsrControlConf();

      JsonMap map = json.getMap("kem");
      if (map != null) {
        ret.setKem(KeystoreConf.parse(map));
      }

      ret.setPeerCerts(FileOrValue.parse(json.getMap("peerCerts")));
      return ret;
    }
  }

}
