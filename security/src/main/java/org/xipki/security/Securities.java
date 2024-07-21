// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.pkcs12.P12SignerFactory;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ReflectiveUtil;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;

import java.io.Closeable;
import java.io.IOException;
import java.security.Security;
import java.util.List;

/**
 * Utility class to initialize {@link SecurityFactory}.
 *
 * @author Lijun Liao (xipki)
 */

public class Securities implements Closeable {

  public static class SecurityConf extends ValidableConf {

    private boolean keyStrongrandomEnabled;

    private boolean signStrongrandomEnabled;

    private int defaultSignerParallelism = 32;

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

  private SecurityFactoryImpl securityFactory;

  public Securities() {
  }

  public SecurityFactory getSecurityFactory() {
    return securityFactory;
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

}
