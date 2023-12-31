// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

/**
 * Responder and ServletPath.
 *
 * @author Lijun Liao (xipki)
 * @since 3.0.1
 */

public class ResponderAndPath {

  private final String servletPath;

  private final Responder responder;

  public ResponderAndPath(String servletPath, Responder responder) {
    this.servletPath = servletPath;
    this.responder = responder;
  }

  public String getServletPath() {
    return servletPath;
  }

  public Responder getResponder() {
    return responder;
  }

}
