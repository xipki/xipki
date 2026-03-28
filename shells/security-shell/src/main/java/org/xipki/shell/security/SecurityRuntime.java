// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.security.Securities;
import org.xipki.shell.ShellUtil;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.io.IoUtil;

import java.io.File;
import java.nio.file.Path;

/**
 * Security Runtime.
 *
 * @author Lijun Liao (xipki)
 */
public class SecurityRuntime {

  private static final String DEFAULT_SECURITY_CONF = "xipki/etc/security.json";

  private static volatile Securities securities;

  /**
   * Returns the lazily initialized security runtime.
   *
   * @return initialized {@link Securities} instance
   * @throws InvalidConfException if the bundled configuration is invalid
   * @throws CodecException if the bundled configuration cannot be parsed
   */
  public static Securities get() throws InvalidConfException, CodecException {
    String expanded = IoUtil.expandFilepath(defaultSecurityConf());
    if (securities != null) {
      return securities;
    }

    synchronized (SecurityRuntime.class) {
      JsonMap confJson = JsonParser.parseMap(Path.of(expanded), true);
      JsonMap securityJson = confJson.getMap("security");
      if (securityJson == null) {
        securityJson = confJson;
      }

      Securities.SecurityConf securityConf = Securities.SecurityConf.parse(securityJson);
      Securities newSecurities = new Securities();
      newSecurities.init(securityConf);
      securities = newSecurities;
      return newSecurities;
    }
  }

  private SecurityRuntime() {
  }

  private static String defaultSecurityConf() {
    String path = ShellUtil.resolveRequired(DEFAULT_SECURITY_CONF);
    return new File(path).isFile() ? path : null;
  }

}
