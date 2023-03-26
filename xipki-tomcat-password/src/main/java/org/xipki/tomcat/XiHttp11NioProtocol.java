// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.tomcat;

import org.apache.coyote.http11.Http11Nio2Protocol;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;

/**
 * Wrapper of @link {@link Http11Nio2Protocol} which allows encrypted passwords.
 *
 * @author Lijun Liao (xipki)
 */
public class XiHttp11NioProtocol extends Http11NioProtocol {

  @Override
  public void setKeystorePass(String certificateKeystorePassword) {
    if (certificateKeystorePassword == null || certificateKeystorePassword.isEmpty()) {
      super.setKeystorePass(certificateKeystorePassword);
    } else {
      super.setKeystorePass(TomcatPasswordResolver.INSTANCE.resolvePassword(certificateKeystorePassword));
    }
  }

  @Override
  public void setKeyPass(String certificateKeyPassword) {
    if (certificateKeyPassword == null || certificateKeyPassword.isEmpty()) {
      super.setKeyPass(certificateKeyPassword);
    } else {
      super.setKeyPass(TomcatPasswordResolver.INSTANCE.resolvePassword(certificateKeyPassword));
    }
  }

  @Override
  public void setSSLPassword(String certificateKeyPassword) {
    if (certificateKeyPassword == null || certificateKeyPassword.isEmpty()) {
      super.setSSLPassword(certificateKeyPassword);
    } else {
      super.setSSLPassword(TomcatPasswordResolver.INSTANCE.resolvePassword(certificateKeyPassword));
    }
  }

  @Override
  public void setTruststorePass(String truststorePassword) {
    if (truststorePassword == null || truststorePassword.isEmpty()) {
      super.setTruststorePass(truststorePassword);
    } else {
      super.setTruststorePass(TomcatPasswordResolver.INSTANCE.resolvePassword(truststorePassword));
    }
  }

  @Override
  public void addSslHostConfig(SSLHostConfig sslHostConfig) {
    TomcatPasswordResolver.INSTANCE.resolvePasswords(sslHostConfig);
    super.addSslHostConfig(sslHostConfig);
  }

}
