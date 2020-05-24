/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security;

import java.io.Closeable;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.password.Passwords;
import org.xipki.password.Passwords.PasswordConf;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11CryptServiceFactoryImpl;
import org.xipki.security.pkcs11.P11ModuleFactory;
import org.xipki.security.pkcs11.P11ModuleFactoryRegisterImpl;
import org.xipki.security.pkcs11.P11SignerFactory;
import org.xipki.security.pkcs11.Pkcs11conf;
import org.xipki.security.pkcs11.iaik.IaikP11ModuleFactory;
import org.xipki.security.pkcs12.P12SignerFactory;
import org.xipki.util.CollectionUtil;
import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.InvalidConfException;
import org.xipki.util.LogUtil;
import org.xipki.util.ValidatableConf;

import com.alibaba.fastjson.JSON;

/**
 * Utility class to initialize {@link SecurityFactory} and {@link P11CryptServiceFactory}.
 *
 * @author Lijun Liao
 */

public class Securities implements Closeable {

  public static class KeystoreConf extends ValidatableConf {

    private String type;

    private FileOrBinary keystore;

    private String password;

    public String getType() {
      return type;
    }

    public void setType(String value) {
      this.type = value;
    }

    public FileOrBinary getKeystore() {
      return keystore;
    }

    public void setKeystore(FileOrBinary value) {
      this.keystore = value;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(String value) {
      this.password = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(type, "type");
      validate(keystore);
    }

  } // class KeystoreConf

  public static class SecurityConf extends ValidatableConf {

    private boolean keyStrongrandomEnabled;

    private boolean signStrongrandomEnabled;

    private int defaultSignerParallelism = 32;

    private FileOrValue pkcs11Conf;

    private PasswordConf password;

    public static final SecurityConf DEFAULT;

    static {
      DEFAULT = new SecurityConf();
    }

    /**
     * list of classes that implement org.xipki.security.SignerFactory
     */
    private List<String> signerFactories;

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

    public PasswordConf getPassword() {
      return password == null ? PasswordConf.DEFAULT : password;
    }

    public void setPassword(PasswordConf password) {
      this.password = password;
    }

    public List<String> getSignerFactories() {
      return signerFactories;
    }

    public void setSignerFactories(List<String> signerFactories) {
      this.signerFactories = signerFactories;
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(password);
    }

  } // class SecurityConf

  private static final Logger LOG = LoggerFactory.getLogger(Securities.class);

  private P11ModuleFactoryRegisterImpl p11ModuleFactoryRegister;

  private P11CryptServiceFactoryImpl p11CryptServiceFactory;

  private SecurityFactoryImpl securityFactory;

  private List<P11ModuleFactory> p11ModuleFactories;

  public Securities() {
    this(createDefaultFactories());
  }

  public Securities(List<P11ModuleFactory> p11ModuleFactories) {
    this.p11ModuleFactories = p11ModuleFactories != null
        ? new ArrayList<>(p11ModuleFactories) : Collections.emptyList();
  }

  private static List<P11ModuleFactory> createDefaultFactories() {
    List<P11ModuleFactory> factories = new ArrayList<>(3);
    factories.add(new IaikP11ModuleFactory());

    String[] classNames = {
        "org.xipki.security.pkcs11.emulator.EmulatorP11ModuleFactory",
        "org.xipki.security.pkcs11.proxy.ProxyP11ModuleFactory"
    };
    ClassLoader cl = Securities.class.getClassLoader();

    for (String className : classNames) {
      Class<?> clazz = null;
      try {
        clazz = cl.loadClass(className);
      } catch (ClassNotFoundException ex) {
        LOG.info("{} not in the classpath, ignore it", className);
      }

      try {
        factories.add((P11ModuleFactory) clazz.newInstance());
      } catch (InstantiationException | IllegalAccessException ex) {
        LogUtil.error(LOG, ex, "could not create new instance of " + className);
      }
    }

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

    initSecurityFactory(conf);
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

  private void initSecurityFactory(SecurityConf conf) throws IOException, InvalidConfException {
    Passwords passwords = new Passwords();
    passwords.init(conf.getPassword());

    securityFactory = new SecurityFactoryImpl();

    securityFactory.setStrongRandom4SignEnabled(conf.isSignStrongrandomEnabled());
    securityFactory.setStrongRandom4KeyEnabled(conf.isKeyStrongrandomEnabled());
    securityFactory.setDefaultSignerParallelism(conf.getDefaultSignerParallelism());

    SignerFactoryRegisterImpl signerFactoryRegister = new SignerFactoryRegisterImpl();
    securityFactory.setSignerFactoryRegister(signerFactoryRegister);
    securityFactory.setPasswordResolver(passwords.getPasswordResolver());

    // PKCS#12
    initSecurityPkcs12(signerFactoryRegister);

    // PKCS#11
    if (conf.getPkcs11Conf() != null) {
      initSecurityPkcs11(conf.getPkcs11Conf(), signerFactoryRegister,
          passwords.getPasswordResolver());
    }

    // register additional SignerFactories
    if (CollectionUtil.isNotEmpty(conf.getSignerFactories())) {
      for (String className : conf.getSignerFactories()) {
        try {
          Class<?> clazz = Class.forName(className);
          SignerFactory factory = (SignerFactory) clazz.newInstance();
          signerFactoryRegister.registFactory(factory);
        } catch (ClassCastException | ClassNotFoundException | IllegalAccessException
            | InstantiationException ex) {
          throw new InvalidConfException("error caught while initializing SignerFactory "
              + className + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      }
    }

  } // method initSecurityFactory

  private void initSecurityPkcs12(SignerFactoryRegisterImpl signerFactoryRegister)
      throws IOException {
    P12SignerFactory p12SignerFactory = new P12SignerFactory();
    p12SignerFactory.setSecurityFactory(securityFactory);
    signerFactoryRegister.registFactory(p12SignerFactory);
  } // method initSecurityPkcs12

  private void initSecurityPkcs11(FileOrValue pkcs11Conf,
      SignerFactoryRegisterImpl signerFactoryRegister, PasswordResolver passwordResolver)
          throws InvalidConfException {
    p11ModuleFactoryRegister = new P11ModuleFactoryRegisterImpl();
    for (P11ModuleFactory m : p11ModuleFactories) {
      p11ModuleFactoryRegister.registFactory(m);
    }

    p11CryptServiceFactory = new P11CryptServiceFactoryImpl();
    p11CryptServiceFactory.setP11ModuleFactoryRegister(p11ModuleFactoryRegister);
    p11CryptServiceFactory.setPasswordResolver(passwordResolver);

    Pkcs11conf pkcs11ConfObj;
    try {
      pkcs11ConfObj = JSON.parseObject(pkcs11Conf.readContent(), Pkcs11conf.class);
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
