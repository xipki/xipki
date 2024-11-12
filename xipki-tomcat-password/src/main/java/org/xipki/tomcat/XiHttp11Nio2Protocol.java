// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.tomcat;

import org.apache.coyote.http11.Http11Nio2Protocol;
import org.apache.tomcat.util.net.SSLHostConfig;

/**
 * Wrapper of @link {@link Http11Nio2Protocol} which allows encrypted passwords.
 *
 * @author Lijun Liao (xipki)
 */
public class XiHttp11Nio2Protocol extends Http11Nio2Protocol {

  @Override
  public void addSslHostConfig(SSLHostConfig sslHostConfig) {
    TomcatPasswordResolver.INSTANCE.resolvePasswords(sslHostConfig);
    super.addSslHostConfig(sslHostConfig);
  }

}
