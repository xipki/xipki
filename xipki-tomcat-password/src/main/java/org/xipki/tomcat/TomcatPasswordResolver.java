// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.tomcat;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.xipki.password.PasswordResolver;
import org.xipki.password.Passwords;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Utility class to resolve password for apache tomcat web server.
 *
 * @author Lijun Liao (xipki)
 */
public class TomcatPasswordResolver {

  public static TomcatPasswordResolver INSTANCE = new TomcatPasswordResolver();

  private boolean passwordResolverInitialized = false;
  private boolean passwordResolverInitFailed = false;
  private PasswordResolver passwordResolver;

  public void resolvePasswords(SSLHostConfig sslHostConfig) {
    String pwd = sslHostConfig.getTruststorePassword();
    if (pwd != null) {
      sslHostConfig.setTruststorePassword(resolvePassword(pwd));
    }

    pwd = sslHostConfig.getCertificateKeystorePassword();
    if (pwd != null) {
      sslHostConfig.setCertificateKeystorePassword(resolvePassword(pwd));
    }

    pwd = sslHostConfig.getCertificateKeyPassword();
    if (pwd != null) {
      sslHostConfig.setCertificateKeyPassword(resolvePassword(pwd));
    }

    Set<SSLHostConfigCertificate> certificates = sslHostConfig.getCertificates();
    for (SSLHostConfigCertificate certificate : certificates) {
      pwd = certificate.getCertificateKeyPassword();
      if (pwd != null) {
        certificate.setCertificateKeyPassword(resolvePassword(pwd));
      }
      pwd = certificate.getCertificateKeystorePassword();
      if (pwd != null) {
        certificate.setCertificateKeystorePassword(resolvePassword(pwd));
      }
    }
  }

  private synchronized void initPasswordResolver() {
    if (passwordResolverInitialized) {
      return;
    }

    try {
      Properties sysProps = System.getProperties();
      String confFile = sysProps.getProperty("XIPKI_PASSWORD_CFG");
      if (confFile == null) {
        String xipkiBase = sysProps.getProperty("XIPKI_BASE");
        if (xipkiBase != null) {
          Path p = Paths.get(xipkiBase, "security", "password.cfg");
          if (Files.exists(p)) {
            confFile = p.toString();
          }
        }
      }

      Passwords.PasswordConf passwordConf = new Passwords.PasswordConf();
      if (confFile != null) {
        confFile = solveVariables(confFile, 0, sysProps);
        Properties passwordCfg = new Properties();
        try (FileReader reader = new FileReader(confFile)){
          passwordCfg.load(reader);
          String text = passwordCfg.getProperty("masterPasswordCallback");
          if (text != null && !text.isEmpty()) {
            passwordConf.setMasterPasswordCallback(solveVariables(text, 0, sysProps));
          }

          text = passwordCfg.getProperty("singlePasswordResolvers");
          if (text != null && !text.trim().isEmpty()) {
            StringTokenizer tokenizer = new StringTokenizer(text.trim(), " ,;:");
            List<String> singleResolvers = new LinkedList<>();
            while (tokenizer.hasMoreTokens()) {
              singleResolvers.add(tokenizer.nextToken());
            }
            passwordConf.setSinglePasswordResolvers(singleResolvers);
          }
        }
      }

      Passwords passwords = new Passwords();
      passwords.init(passwordConf);
      passwordResolver = passwords.getPasswordResolver();
      passwordResolverInitFailed = false;
    } catch (Exception e) {
      passwordResolverInitFailed = true;
    } finally {
      passwordResolverInitialized = true;
    }
  }

  private static String solveVariables(String line, int offset, Properties properties) {
    if (offset + 4 >= line.length()) {
      return line;
    }

    int startIndex = line.indexOf("${", offset);
    if (startIndex == -1) {
      return line;
    }

    int endIndex = line.indexOf("}", startIndex + 2);
    if (endIndex == -1) {
      return line;
    }

    String variable = line.substring(startIndex, endIndex + 1);
    String variableName = variable.substring(2, variable.length() - 1);
    String value = properties.getProperty(variableName);

    int newOffset;
    if (value != null) {
      line = line.substring(0, startIndex) + value + line.substring(endIndex + 1);
      newOffset = startIndex + value.length() + 1;
    } else {
      newOffset = endIndex + 1;
    }

    return solveVariables(line, newOffset, properties);
  }

  String resolvePassword(String password) {
    if (password == null || password.isEmpty()) {
      return password;
    }

    int sepIndex = password.indexOf(':');
    if (sepIndex == -1) {
      return password;
    }

    initPasswordResolver();
    if (passwordResolverInitFailed) {
      return password;
    }

    try {
      char[] pwd = passwordResolver.resolvePassword(password);
      return new String(pwd);
    } catch (Exception e) {
      System.err.println("ERROR: could not resolve password");
      return password;
    }
  }

}
