// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.tomcat;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.xipki.password.Passwords;

import java.util.Set;

/**
 * Utility class to resolve password for apache tomcat web server.
 *
 * @author Lijun Liao (xipki)
 */
public class TomcatPasswordResolver {

  public static final TomcatPasswordResolver INSTANCE = new TomcatPasswordResolver();

  public void resolvePasswords(SSLHostConfig sslHostConfig) {
    String pwd = sslHostConfig.getTruststorePassword();
    if (pwd != null) {
      sslHostConfig.setTruststorePassword(resolvePassword(pwd));
    }

    pwd = sslHostConfig.getTruststorePassword();
    if (pwd != null) {
      sslHostConfig.setTruststorePassword(resolvePassword(pwd));
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

  String resolvePassword(String password) {
    if (password == null || password.isEmpty()) {
      return password;
    }

    int sepIndex = password.indexOf(':');
    if (sepIndex == -1) {
      return password;
    }

    try {
      char[] pwd = Passwords.resolvePassword(password);
      return new String(pwd);
    } catch (Exception e) {
      System.err.println("ERROR: xipki-tomcat-password: could not resolve password");
      return password;
    }
  }

}
