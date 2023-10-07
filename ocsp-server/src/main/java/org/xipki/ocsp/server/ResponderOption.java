// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.util.Args;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Responder option.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
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
    String str = Args.notNull(conf, "conf").getMode();
    if (str == null || StringUtil.orEqualsIgnoreCase(str, "RFC6960", "RFC 6960")) {
      this.mode = OcspMode.RFC6960;
    } else if (StringUtil.orEqualsIgnoreCase(str, "RFC2560", "RFC 2560")) {
      this.mode = OcspMode.RFC2560;
    } else {
      throw new InvalidConfException("invalid OCSP mode '" + str + "'");
    }

    this.signerName = conf.getSigner();
    this.requestOptionName = conf.getRequest();
    this.responseOptionName = conf.getResponse();
    this.inheritCaRevocation = conf.isInheritCaRevocation();

    List<String> list = new ArrayList<>(conf.getStores());
    this.storeNames = Collections.unmodifiableList(list);

    List<String> paths = conf.getServletPaths();
    for (String path : paths) {
      if (path.isEmpty()) {
        continue;
      }

      if (path.charAt(0) != '/') {
        throw new InvalidConfException("servlet path '" + path + "' must start with '/'");
      }
    }
    list = new ArrayList<>(paths);
    this.servletPaths = Collections.unmodifiableList(list);
  } // constructor

  public OcspMode getMode() {
    return mode;
  }

  public boolean isInheritCaRevocation() {
    return inheritCaRevocation;
  }

  public String getSignerName() {
    return signerName;
  }

  public String getRequestOptionName() {
    return requestOptionName;
  }

  public String getResponseOptionName() {
    return responseOptionName;
  }

  public List<String> getStoreNames() {
    return storeNames;
  }

  public List<String> getServletPaths() {
    return servletPaths;
  }

}
