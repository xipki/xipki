// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.util.codec.Args;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.misc.StringUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Responder option.
 *
 * @author Lijun Liao (xipki)
 */

class ResponderOption {

  public enum OcspMode {

    RFC2560,
    RFC6960

  }

  private final OcspMode mode;

  private final boolean inheritCaRevocation;

  private final String requestOptionName;

  private final String responseOptionName;

  private final String signerName;

  private final List<String> storeNames;

  private final List<String> servletPaths;

  ResponderOption(OcspServerConf.Responder conf) throws InvalidConfException {
    String str = Args.notNull(conf, "conf").mode();
    if (str == null
        || StringUtil.orEqualsIgnoreCase(str, "RFC6960", "RFC 6960")) {
      this.mode = OcspMode.RFC6960;
    } else if (StringUtil.orEqualsIgnoreCase(str, "RFC2560", "RFC 2560")) {
      this.mode = OcspMode.RFC2560;
    } else {
      throw new InvalidConfException("invalid OCSP mode '" + str + "'");
    }

    this.signerName = conf.signer();
    this.requestOptionName = conf.request();
    this.responseOptionName = conf.response();
    this.inheritCaRevocation = conf.isInheritCaRevocation();

    List<String> list = new ArrayList<>(conf.stores());
    this.storeNames = Collections.unmodifiableList(list);

    List<String> paths = conf.servletPaths();
    for (String path : paths) {
      if (path.isEmpty()) {
        continue;
      }

      if (path.charAt(0) != '/') {
        throw new InvalidConfException("servlet path '" + path
            + "' must start with '/'");
      }
    }
    list = new ArrayList<>(paths);
    this.servletPaths = Collections.unmodifiableList(list);
  } // constructor

  public OcspMode mode() {
    return mode;
  }

  public boolean isInheritCaRevocation() {
    return inheritCaRevocation;
  }

  public String signerName() {
    return signerName;
  }

  public String requestOptionName() {
    return requestOptionName;
  }

  public String responseOptionName() {
    return responseOptionName;
  }

  public List<String> storeNames() {
    return storeNames;
  }

  public List<String> servletPaths() {
    return servletPaths;
  }

}
