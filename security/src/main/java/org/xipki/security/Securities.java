// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11CryptServiceFactoryImpl;
import org.xipki.security.pkcs11.P11SignerFactory;
import org.xipki.security.pkcs11.P11SystemConf;
import org.xipki.security.pkcs12.P12SignerFactory;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.ReflectiveUtil;
import org.xipki.util.io.FileOrValue;
import org.xipki.util.password.PasswordResolverException;

import java.io.Closeable;
import java.io.IOException;
import java.security.Security;
import java.util.List;

/**
 * Utility class to initialize {@link SecurityFactory} and
 * {@link P11CryptServiceFactory}.
 *
 * @author Lijun Liao (xipki)
 */
public class Securities implements Closeable {

  public static class SecurityConf {

    private boolean keyStrongrandomEnabled;

    private boolean signStrongrandomEnabled;

    private int defaultSignerParallelism = 32;

    private FileOrValue pkcs11Conf;

    /**
     * list of classes that implement {@link SignerFactory}
     */
    private List<String> signerFactories;

    public static final SecurityConf DEFAULT;

    static {
      DEFAULT = new SecurityConf();
    }

    public boolean isKeyStrongrandomEnabled() {
      return keyStrongrandomEnabled;
    }

    public void setKeyStrongrandomEnabled(boolean keyStrongrandomEnabled) {
      this.keyStrongrandomEnabled = keyStrongrandomEnabled;
    }

    public boolean isSignStrongrandomEnabled() {
      return signStrongrandomEnabled;
    }

    public void setSignStrongrandomEnabled(boolean signStrongrandomEnabled) {
      this.signStrongrandomEnabled = signStrongrandomEnabled;
    }

    public int defaultSignerParallelism() {
      return defaultSignerParallelism;
    }

    public void setDefaultSignerParallelism(int defaultSignerParallelism) {
      this.defaultSignerParallelism = defaultSignerParallelism;
    }

    public FileOrValue pkcs11Conf() {
      return pkcs11Conf;
    }

    public void setPkcs11Conf(FileOrValue pkcs11Conf) {
      this.pkcs11Conf = pkcs11Conf;
    }

    @Deprecated
    public void setPassword(Object password) {
      LOG.warn("ignored password configuration");
    }

    public List<String> signerFactories() {
      return signerFactories;
    }

    public void setSignerFactories(List<String> signerFactories) {
      this.signerFactories = signerFactories;
    }

    @Deprecated
    public void setKeypairGeneratorFactories(
        List<String> keypairGeneratorFactories) {
      if (keypairGeneratorFactories != null &&
          !keypairGeneratorFactories.isEmpty()) {
        LOG.warn("keypairGeneratorFactories is not allowed");
      }
    }

    public static SecurityConf parse(JsonMap json) throws CodecException {
      SecurityConf ret = new SecurityConf();

      Boolean b = json.getBool("keyStrongrandomEnabled");
      if (b != null) {
        ret.setKeyStrongrandomEnabled(b);
      }

      b = json.getBool("signStrongrandomEnabled");
      if (b != null) {
        ret.setSignStrongrandomEnabled(b);
      }

      Integer i = json.getInt("defaultSignerParallelism");
      if (i != null) {
        ret.setDefaultSignerParallelism(i);
      }

      ret.setPkcs11Conf(FileOrValue.parse(json.getMap("pkcs11Conf")));
      ret.setSignerFactories(json.getStringList("signerFactories"));

      return ret;
    }

  } // class SecurityConf

  private static final Logger LOG = LoggerFactory.getLogger(Securities.class);

  private P11CryptServiceFactoryImpl p11CryptServiceFactory;

  private SecurityFactoryImpl securityFactory;

  public Securities() {
  }

  public SecurityFactory securityFactory() {
    return securityFactory;
  }

  public P11CryptServiceFactory p11CryptServiceFactory() {
    return p11CryptServiceFactory;
  }

  public void init() throws IOException, InvalidConfException {
    init(null);
  }

  public void init(SecurityConf conf) throws IOException, InvalidConfException {
    if (Security.getProvider("BC") == null) {
      LOG.info("add BouncyCastleProvider");
      Security.addProvider(KeyUtil.newBouncyCastleProvider());
    } else {
      LOG.info("BouncyCastleProvider already added");
    }

    if (conf == null) {
      conf = SecurityConf.DEFAULT;
    }

    try {
      initSecurityFactory(conf);
    } catch (PasswordResolverException e) {
      LOG.error("could not initialize passwords", e);
      throw new InvalidConfException(e.getMessage());
    }
  }

  @Override
  public void close() {
    if (p11CryptServiceFactory != null) {
      try {
        p11CryptServiceFactory.close();
      } catch (Throwable th) {
        LOG.error("error while closing P11CryptServiceFactory", th);
      }
      this.p11CryptServiceFactory = null;
    }
  } // method close

  private void initSecurityFactory(SecurityConf conf)
      throws PasswordResolverException, InvalidConfException {
    securityFactory = new SecurityFactoryImpl();

    securityFactory.setStrongRandom4SignEnabled(
        conf.isSignStrongrandomEnabled());
    securityFactory.setStrongRandom4KeyEnabled(
        conf.isKeyStrongrandomEnabled());
    securityFactory.setDefaultSignerParallelism(
        conf.defaultSignerParallelism());

    //----- Factories
    SignerFactoryRegisterImpl signerFactoryRegister =
        new SignerFactoryRegisterImpl();
    securityFactory.setSignerFactoryRegister(signerFactoryRegister);

    // PKCS#12 (software)
    P12SignerFactory p12SignerFactory = new P12SignerFactory();
    p12SignerFactory.setSecurityFactory(securityFactory);
    signerFactoryRegister.registFactory(p12SignerFactory);

    // PKCS#11
    if (conf.pkcs11Conf() != null) {
      initSecurityPkcs11(conf.pkcs11Conf(), signerFactoryRegister);
    }

    // register additional SignerFactories
    if (CollectionUtil.isNotEmpty(conf.signerFactories())) {
      for (String className : conf.signerFactories()) {
        SignerFactory factory;
        try {
          factory = ReflectiveUtil.newInstance(className);
        } catch (ObjectCreationException ex) {
          throw new InvalidConfException(ex.getMessage(), ex);
        }
        signerFactoryRegister.registFactory(factory);
      }
    }
  } // method initSecurityFactory

  private void initSecurityPkcs11(
      FileOrValue pkcs11Conf, SignerFactoryRegisterImpl signerFactoryRegister)
      throws InvalidConfException {
    p11CryptServiceFactory = new P11CryptServiceFactoryImpl();

    P11SystemConf pkcs11ConfObj = P11SystemConf.parse(pkcs11Conf);
    p11CryptServiceFactory.setPkcs11Conf(pkcs11ConfObj);

    p11CryptServiceFactory.init();

    P11SignerFactory p11SignerFactory = new P11SignerFactory();
    p11SignerFactory.setSecurityFactory(securityFactory);
    p11SignerFactory.setP11CryptServiceFactory(p11CryptServiceFactory);

    signerFactoryRegister.registFactory(p11SignerFactory);
  }

}
