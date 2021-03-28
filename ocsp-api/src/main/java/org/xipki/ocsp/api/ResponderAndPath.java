/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ocsp.api;

/**
 * Responder and ServletPath.
 *
 * @author Lijun Liao
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
