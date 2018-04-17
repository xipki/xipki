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

package org.xipki.ocsp.war;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.ocsp.api.internal.OcspStoreFactoryRegisterImpl;
import org.xipki.ocsp.server.impl.OcspServerImpl;
import org.xipki.ocsp.server.servlet.ServletHelper;
import org.xipki.password.PasswordResolverImpl;
import org.xipki.security.Providers;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.SignerFactoryRegisterImpl;
import org.xipki.security.pkcs11.P11CryptServiceFactoryImpl;
import org.xipki.security.pkcs11.P11ModuleFactoryRegisterImpl;
import org.xipki.security.pkcs11.emulator.EmulatorP11ModuleFactory;
import org.xipki.security.pkcs11.iaik.IaikP11ModuleFactory;
import org.xipki.security.pkcs11.provider.XiProviderRegister;
import org.xipki.security.pkcs11.proxy.ProxyP11ModuleFactory;

public class OcspRuntime {

  public static final String PROP_XIPKI_CONF_DIR = "xipki.conf.dir";

  public static final String DFLT_XIPKI_CONF_DIR = "~/.xipki";

  private static final String CONF_FILE_PASSWORD = "org.xipki.password.cfg";

  private static final String CONF_FILE_SECURITY = "org.xipki.security.cfg";

  private static final Logger LOG = LoggerFactory.getLogger(OcspRuntime.class);

  private static String confDir;

  private static Providers providers;

  private static P11CryptServiceFactoryImpl p11CryptServiceFactory;

  private static P11ModuleFactoryRegisterImpl p11ModuleFactoryRegister;

  private static OcspServerImpl ocspServer;

  private static boolean initialized;

  private static Throwable initializationError;

  static {
    confDir = System.getProperty(PROP_XIPKI_CONF_DIR);
    if (confDir == null) {
      confDir = DFLT_XIPKI_CONF_DIR;
    }
    confDir = IoUtil.expandFilepath(confDir);
  }

  public static void main(String[] args) {
    init();
  }

  public static void init() {
    if (initializationError != null) {
      return;
    }

    if (initialized) {
      return;
    }

    try {
      // password
      Properties props = getProps(CONF_FILE_PASSWORD);
      PasswordResolverImpl passwordResolver = new PasswordResolverImpl();
      passwordResolver.setMasterPasswordCallback(getProp(props, "masterPasswordCallback", "PBE-GUI"));
      passwordResolver.init();

      // security
      props = getProps(CONF_FILE_SECURITY);

      providers = new Providers();
      providers.init();

      // security - pkcs#11
      p11ModuleFactoryRegister = new P11ModuleFactoryRegisterImpl();
      p11ModuleFactoryRegister.bindService(new EmulatorP11ModuleFactory());
      p11ModuleFactoryRegister.bindService(new IaikP11ModuleFactory());
      p11ModuleFactoryRegister.bindService(new ProxyP11ModuleFactory());

      p11CryptServiceFactory = new P11CryptServiceFactoryImpl();
      String p11ConfFile = getProp(props, "pkcs11.confFile", "");
      p11CryptServiceFactory.setPkcs11ConfFile(p11ConfFile);
      p11CryptServiceFactory.setPasswordResolver(passwordResolver);
      p11CryptServiceFactory.setP11ModuleFactoryRegister(p11ModuleFactoryRegister);
      p11CryptServiceFactory.init();

      SignerFactoryRegisterImpl signerFactoryRegister = new SignerFactoryRegisterImpl();
      signerFactoryRegister.setP11CryptServiceFactory(p11CryptServiceFactory);

      SecurityFactoryImpl securityFactory = new SecurityFactoryImpl();
      securityFactory.setStrongRandom4KeyEnabled(
          getBooleanProp(props, "key.strongrandom.enabled", false));
      securityFactory.setStrongRandom4SignEnabled(
          getBooleanProp(props, "sign.strongrandom.enabled", false));
      securityFactory.setDefaultSignerParallelism(
          getIntProp(props, "defaultSignerParallelism", 32));
      securityFactory.setPasswordResolver(passwordResolver);
      securityFactory.setSignerFactoryRegister(signerFactoryRegister);

      XiProviderRegister xiProviderRegister = new XiProviderRegister();
      xiProviderRegister.regist();

      // OCSP
      OcspStoreFactoryRegisterImpl ocspStoreFactoryRegister = new OcspStoreFactoryRegisterImpl();
      ocspServer = new OcspServerImpl();
      ocspServer.setConfFile(new File(confDir, "ocsp-responder.xml").getPath());
      ocspServer.setSecurityFactory(securityFactory);
      ocspServer.setOcspStoreFactoryRegister(ocspStoreFactoryRegister);
      ocspServer.init();

      // Servlet
      ServletHelper servletHelper = new ServletHelper();
      servletHelper.setServer(ocspServer);
      initialized = true;
    } catch (Throwable th) {
      initializationError = th;
      LOG.error("coult not initialize");
    }
  }

  public static void shutdown() {
    // shutdown in reversed order
    if (ocspServer != null) {
      try {
        ocspServer.shutdown();
      } catch (Throwable th) {
        LOG.error("cannot shutdown OCSPServerImpl", th);
      }
      ocspServer = null;
    }

    if (p11CryptServiceFactory != null) {
      try {
        p11CryptServiceFactory.shutdown();
      } catch (Throwable th) {
        LOG.error("could not shutdown P11CryptServiceFactoryImpl", th);
      }
      p11CryptServiceFactory = null;
    }

    if (providers != null) {
      try {
        providers.shutdown();
      } catch (Throwable th) {
        LOG.error("cannot shutdown Providers", th);
      }
      providers = null;
    }

    if (p11ModuleFactoryRegister != null) {
      try {
        p11ModuleFactoryRegister.shutdown();
      } catch (Throwable th) {
        LOG.error("cannot shutdown P11ModuleFactoryRegisterImpl", th);
      }
      p11ModuleFactoryRegister = null;
    }

    initialized = false;
    initializationError = null;
  }

  private static Properties getProps(String propsFile) throws IOException {
    Properties props = new Properties();
    FileInputStream fis = new FileInputStream(new File(confDir, propsFile));
    try {
      props.load(fis);
    } finally {
      fis.close();
    }

    return props;
  }

  private static String getProp(Properties props, String propKey, String dfltValue) {
    String value = props.getProperty(propKey);
    return (value == null) ? dfltValue : value;
  }

  private static boolean getBooleanProp(Properties props, String propKey, boolean dfltValue) {
    String value = props.getProperty(propKey);
    return (value == null) ? dfltValue : Boolean.valueOf(value);
  }

  private static int getIntProp(Properties props, String propKey, int dfltValue) {
    String value = props.getProperty(propKey);
    return (value == null) ? dfltValue : Integer.valueOf(value);
  }

}
