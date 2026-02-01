// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

/**
 * Responder and ServletPath.
 *
 * @author Lijun Liao (xipki)
 */

public class ResponderAndPath {

  private final String servletPath;

  private final Responder responder;

  public ResponderAndPath(String servletPath, Responder responder) {
    this.servletPath = servletPath;
    this.responder = responder;
  }

  public String servletPath() {
    return servletPath;
  }

  public Responder responder() {
    return responder;
  }

}
