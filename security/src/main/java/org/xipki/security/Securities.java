// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.pkcs11.NativeP11ModuleFactory;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11CryptServiceFactoryImpl;
import org.xipki.security.pkcs11.P11ModuleFactory;
import org.xipki.security.pkcs11.P11ModuleFactoryRegisterImpl;
import org.xipki.security.pkcs11.P11SignerFactory;
import org.xipki.security.pkcs11.Pkcs11conf;
import org.xipki.security.pkcs11.emulator.EmulatorP11ModuleFactory;
import org.xipki.security.pkcs11.hsmproxy.HsmProxyP11ModuleFactory;
import org.xipki.security.pkcs12.P12SignerFactory;
import org.xipki.util.CollectionUtil;
import org.xipki.util.FileOrValue;
import org.xipki.util.JSON;
import org.xipki.util.ReflectiveUtil;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import java.io.Closeable;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Utility class to initialize {@link SecurityFactory} and {@link P11CryptServiceFactory}.
 *
 * @author Lijun Liao (xipki)
 */

public class Securities implements Closeable {

  public static class SecurityConf extends ValidableConf {

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

    public int getDefaultSignerParallelism() {
      return defaultSignerParallelism;
    }

    public void setDefaultSignerParallelism(int defaultSignerParallelism) {
      this.defaultSignerParallelism = defaultSignerParallelism;
    }

    public FileOrValue getPkcs11Conf() {
      return pkcs11Conf;
    }

    public void setPkcs11Conf(FileOrValue pkcs11Conf) {
      this.pkcs11Conf = pkcs11Conf;
    }

    @Deprecated
    public void setPassword(Object password) {
      LOG.warn("ignored password configuration");
    }

    public List<String> getSignerFactories() {
      return signerFactories;
    }

    public void setSignerFactories(List<String> signerFactories) {
      this.signerFactories = signerFactories;
    }

    @Deprecated
    public void setKeypairGeneratorFactories(List<String> keypairGeneratorFactories) {
      if (keypairGeneratorFactories != null && !keypairGeneratorFactories.isEmpty()) {
        LOG.warn("keypairGeneratorFactories is not allowed");
      }
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class SecurityConf

  private static final Logger LOG = LoggerFactory.getLogger(Securities.class);

  private P11ModuleFactoryRegisterImpl p11ModuleFactoryRegister;

  private P11CryptServiceFactoryImpl p11CryptServiceFactory;

  private SecurityFactoryImpl securityFactory;

  private final List<P11ModuleFactory> p11ModuleFactories;

  public Securities() {
    this(createDefaultFactories());
  }

  public Securities(List<P11ModuleFactory> p11ModuleFactories) {
    this.p11ModuleFactories = p11ModuleFactories != null
        ? new ArrayList<>(p11ModuleFactories) : Collections.emptyList();
  }

  private static List<P11ModuleFactory> createDefaultFactories() {
    List<P11ModuleFactory> factories = new ArrayList<>(3);
    factories.add(new NativeP11ModuleFactory());
    factories.add(new EmulatorP11ModuleFactory());
    factories.add(new HsmProxyP11ModuleFactory());
    return factories;
  }

  public SecurityFactory getSecurityFactory() {
    return securityFactory;
  }

  public P11CryptServiceFactory getP11CryptServiceFactory() {
    return p11CryptServiceFactory;
  }

  public void init() throws IOException, InvalidConfException {
    init(null);
  }

  public void init(SecurityConf conf) throws IOException, InvalidConfException {
    if (Security.getProvider("BC") == null) {
      LOG.info("add BouncyCastleProvider");
      Security.addProvider(new BouncyCastleProvider());
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
    if (p11ModuleFactoryRegister != null) {
      try {
        p11ModuleFactoryRegister.close();
      } catch (Throwable th) {
        LOG.error("error while closing P11ModuleFactoryRegister", th);
      }
      p11ModuleFactoryRegister = null;
    }

    if (p11CryptServiceFactory != null) {
      try {
        p11CryptServiceFactory.close();
      } catch (Throwable th) {
        LOG.error("error while closing P11CryptServiceFactory", th);
      }
      this.p11CryptServiceFactory = null;
    }
  } // method close

  private void initSecurityFactory(SecurityConf conf) throws PasswordResolverException, InvalidConfException {
    securityFactory = new SecurityFactoryImpl();

    securityFactory.setStrongRandom4SignEnabled(conf.isSignStrongrandomEnabled());
    securityFactory.setStrongRandom4KeyEnabled(conf.isKeyStrongrandomEnabled());
    securityFactory.setDefaultSignerParallelism(conf.getDefaultSignerParallelism());

    //----- Factories
    SignerFactoryRegisterImpl signerFactoryRegister = new SignerFactoryRegisterImpl();
    securityFactory.setSignerFactoryRegister(signerFactoryRegister);

    // PKCS#12 (software)
    P12SignerFactory p12SignerFactory = new P12SignerFactory();
    p12SignerFactory.setSecurityFactory(securityFactory);
    signerFactoryRegister.registFactory(p12SignerFactory);

    // PKCS#11
    if (conf.getPkcs11Conf() != null) {
      initSecurityPkcs11(conf.getPkcs11Conf(), signerFactoryRegister);
    }

    // register additional SignerFactories
    if (CollectionUtil.isNotEmpty(conf.getSignerFactories())) {
      for (String className : conf.getSignerFactories()) {
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
    p11ModuleFactoryRegister = new P11ModuleFactoryRegisterImpl();
    for (P11ModuleFactory m : p11ModuleFactories) {
      p11ModuleFactoryRegister.registFactory(m);
    }

    p11CryptServiceFactory = new P11CryptServiceFactoryImpl(p11ModuleFactoryRegister);

    Pkcs11conf pkcs11ConfObj;
    try {
      pkcs11ConfObj = JSON.parseConf(pkcs11Conf.readContent(), Pkcs11conf.class);
    } catch (IOException ex) {
      throw new InvalidConfException("could not create P11Conf: " + ex.getMessage(), ex);
    }
    p11CryptServiceFactory.setPkcs11Conf(pkcs11ConfObj);

    p11CryptServiceFactory.init();

    P11SignerFactory p11SignerFactory = new P11SignerFactory();
    p11SignerFactory.setSecurityFactory(securityFactory);
    p11SignerFactory.setP11CryptServiceFactory(p11CryptServiceFactory);

    signerFactoryRegister.registFactory(p11SignerFactory);
  } // method initSecurityPkcs11

}
