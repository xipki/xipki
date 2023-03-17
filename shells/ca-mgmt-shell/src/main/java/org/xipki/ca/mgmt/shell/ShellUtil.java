// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell;

import org.xipki.security.SecurityFactory;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.*;

import java.util.Set;

/**
 * Util class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ShellUtil {

  private ShellUtil() {
  }

  public static String canonicalizeSignerConf(String keystoreType, String signerConf, SecurityFactory securityFactory)
          throws Exception {
    Args.notBlank(keystoreType, "keystoreType");
    Args.notBlank(signerConf, "signerConf");
    Args.notNull(securityFactory, "securityFactory");

    if (!signerConf.contains("file:") && !signerConf.contains("base64:")
        && !signerConf.contains("FILE:") && !signerConf.contains("BASE64:")) {
      return signerConf;
    }

    ConfPairs pairs = new ConfPairs(signerConf);
    String keystoreConf = pairs.value("keystore");
    String passwordHint = pairs.value("password");

    if (passwordHint == null) {
      throw new IllegalArgumentException("password is not set in " + signerConf);
    }

    byte[] keystoreBytes;
    if (StringUtil.startsWithIgnoreCase(keystoreConf, "file:")) {
      String keystoreFile = keystoreConf.substring("file:".length());
      keystoreBytes = IoUtil.read(keystoreFile);
    } else if (StringUtil.startsWithIgnoreCase(keystoreConf, "base64:")) {
      keystoreBytes = Base64.decode(keystoreConf.substring("base64:".length()));
    } else {
      return signerConf;
    }

    pairs.putPair("keystore", "base64:" + Base64.encodeToString(keystoreBytes));
    return pairs.getEncoded();
  } // method canonicalizeSignerConf

  public static int getPermission(Set<String> permissions) throws IllegalCmdParamException {
    int ret = 0;
    for (String permission : permissions) {
      Integer code = PermissionConstants.getPermissionForText(permission);
      if (code == null) {
        throw new IllegalCmdParamException("invalid permission '" + permission + "'");
      }
      ret |= code;
    }
    return ret;
  } // method getPermission

}
