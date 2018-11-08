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

package org.xipki.security;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolverImpl;
import org.xipki.password.SinglePasswordResolver;
import org.xipki.security.pkcs11.P11CryptServiceFactoryImpl;
import org.xipki.security.pkcs11.P11ModuleFactoryRegisterImpl;
import org.xipki.security.pkcs11.PKCS11SignerFactory;
import org.xipki.security.pkcs11.emulator.EmulatorP11ModuleFactory;
import org.xipki.security.pkcs11.iaik.IaikP11ModuleFactory;
import org.xipki.security.pkcs12.PKCS12SignerFactory;
import org.xipki.util.InvalidConfException;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Securities implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(Securities.class);

  private static final String DFLT_PASSWORD_CFG = "xipki/etc/org.xipki.password.cfg";

  private static final String DFLT_SECURITY_CFG = "xipki/etc/org.xipki.security.cfg";

  private String passwordCfg;

  private String securityCfg;

  private PasswordResolverImpl passwordResolver;

  private P11ModuleFactoryRegisterImpl p11ModuleFactoryRegister;

  private P11CryptServiceFactoryImpl p11CryptServiceFactory;

  private SecurityFactoryImpl securityFactory;

  public void setPasswordCfg(String file) {
    this.passwordCfg = file;
  }

  public void setSecuirtyCfg(String file) {
    this.securityCfg = file;
  }

  public SecurityFactory getSecurityFactory() {
    return securityFactory;
  }

  public void init() throws IOException, InvalidConfException {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    initPassword();
    initSecurityFactory();
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
  }

  private void initPassword() throws IOException, InvalidConfException {
    passwordResolver = new PasswordResolverImpl();
    Properties props = loadProperties(passwordCfg, DFLT_PASSWORD_CFG);
    String masterPasswordCallback = getString(props, "masterPassword.callback",
                        "FILE file=xipki/security/masterpassword.secret");
    passwordResolver.setMasterPasswordCallback(masterPasswordCallback);
    passwordResolver.init();

    // register additional SinglePasswordResolvers
    String list = getString(props, "Additional.SinglePasswordResolvers", null);
    String[] classNames = list == null ? null : list.split(", ");
    if (classNames != null) {
      for (String className : classNames) {
        try {
          Class<?> clazz = Class.forName(className);
          SinglePasswordResolver resolver = (SinglePasswordResolver) clazz.newInstance();
          passwordResolver.registResolver(resolver);
        } catch (ClassCastException | ClassNotFoundException | IllegalAccessException
            | InstantiationException ex) {
          throw new InvalidConfException("error caught while initializing SinglePasswordResolver "
              + className + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
      }
    }
  }

  private void initSecurityFactory() throws IOException, InvalidConfException {
    securityFactory = new SecurityFactoryImpl();
    Properties props = loadProperties(securityCfg, DFLT_SECURITY_CFG);
    securityFactory.setStrongRandom4SignEnabled(
        getBoolean(props, "sign.strongrandom.enabled", false));
    securityFactory.setStrongRandom4KeyEnabled(
        getBoolean(props, "key.strongrandom.enabled", false));
    securityFactory.setDefaultSignerParallelism(
        getInt(props, "defaultSignerParallelism", 32));

    SignerFactoryRegisterImpl signerFactoryRegister = new SignerFactoryRegisterImpl();
    securityFactory.setSignerFactoryRegister(signerFactoryRegister);
    securityFactory.setPasswordResolver(passwordResolver);

    // PKCS#12
    initSecurityPkcs12(signerFactoryRegister);

    // PKCS#11
    String pkcs11ConfFile = getString(props, "pkcs11.confFile", "xipki/security/pkcs11-hsm.xml");
    initSecurityPkcs11(pkcs11ConfFile, signerFactoryRegister);

    // register additional SignerFactories
    String list = getString(props, "Additional.SignerFactories", null);
    String[] classNames = list == null ? null : list.split(", ");
    if (classNames != null) {
      for (String className : classNames) {
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

  }

  private void initSecurityPkcs12(SignerFactoryRegisterImpl signerFactoryRegister)
      throws IOException {
    PKCS12SignerFactory p12SignerFactory = new PKCS12SignerFactory();
    p12SignerFactory.setSecurityFactory(securityFactory);
    signerFactoryRegister.registFactory(p12SignerFactory);
  }

  private void initSecurityPkcs11(String pkcs11ConfFile,
      SignerFactoryRegisterImpl signerFactoryRegister)
      throws IOException, InvalidConfException {
    p11ModuleFactoryRegister = new P11ModuleFactoryRegisterImpl();
    p11ModuleFactoryRegister.registFactory(new EmulatorP11ModuleFactory());
    p11ModuleFactoryRegister.registFactory(new IaikP11ModuleFactory());

    p11CryptServiceFactory = new P11CryptServiceFactoryImpl();
    p11CryptServiceFactory.setP11ModuleFactoryRegister(p11ModuleFactoryRegister);
    p11CryptServiceFactory.setPasswordResolver(passwordResolver);
    p11CryptServiceFactory.setPkcs11ConfFile(pkcs11ConfFile);

    p11CryptServiceFactory.init();

    PKCS11SignerFactory p11SignerFactory = new PKCS11SignerFactory();
    p11SignerFactory.setSecurityFactory(securityFactory);
    p11SignerFactory.setP11CryptServiceFactory(p11CryptServiceFactory);

    signerFactoryRegister.registFactory(p11SignerFactory);
  }

  public static Properties loadProperties(String path, String dfltPath) throws IOException {
    return loadProperties(path == null ? dfltPath : path);
  }

  public static Properties loadProperties(String path) throws IOException {
    Path realPath = Paths.get(path);
    if (!Files.exists(realPath)) {
      throw new IOException("File " + path + " does not exist");
    }

    if (!Files.isReadable(realPath)) {
      throw new IOException("File " + path + " is not readable");
    }

    Properties props = new Properties();
    try (InputStream is = Files.newInputStream(realPath)) {
      props.load(is);
    }
    return props;
  }

  public static String getString(Properties props, String key, String dfltValue) {
    String value = props.getProperty(key);
    return value == null ? dfltValue : value;
  }

  public static int getInt(Properties props, String key, int dfltValue) {
    String value = props.getProperty(key);
    return value == null ? dfltValue : Integer.parseInt(value);
  }

  public static boolean getBoolean(Properties props, String key, boolean dfltValue) {
    String value = props.getProperty(key);
    return value == null ? dfltValue : Boolean.parseBoolean(value);
  }

}
