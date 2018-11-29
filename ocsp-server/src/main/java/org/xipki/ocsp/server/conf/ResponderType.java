/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ocsp.server.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class ResponderType extends ValidatableConf {

  /**
   * To answer OCSP request via URI http://example.com/foo/abc, you can use the combination
   * (servlet.alias = '/', servletPath = '/foo/abc') or
   * (servlet.alias = '/foo', servletPath = '/abc').
   */
  private List<String> servletPaths;

  /**
   * Valid values are RFC2560 and RFC6960. If not present, then RFC6960 mode will be applied.
   */
  private String mode;

  /**
   * Whether to consider certificate as revoked if CA is revoked.
   */
  private boolean inheritCaRevocation;

  private String signer;

  private String request;

  private String response;

  private List<String> stores;

  private String name;

  public List<String> getServletPaths() {
    if (servletPaths == null) {
      servletPaths = new LinkedList<>();
    }
    return servletPaths;
  }

  public void setServletPaths(List<String> servletPaths) {
    this.servletPaths = servletPaths;
  }

  public String getMode() {
    return mode;
  }

  public void setMode(String mode) {
    this.mode = mode;
  }

  public boolean isInheritCaRevocation() {
    return inheritCaRevocation;
  }

  public void setInheritCaRevocation(boolean inheritCaRevocation) {
    this.inheritCaRevocation = inheritCaRevocation;
  }

  public String getSigner() {
    return signer;
  }

  public void setSigner(String signer) {
    this.signer = signer;
  }

  public String getRequest() {
    return request;
  }

  public void setRequest(String request) {
    this.request = request;
  }

  public String getResponse() {
    return response;
  }

  public void setResponse(String response) {
    this.response = response;
  }

  public List<String> getStores() {
    if (stores == null) {
      stores = new LinkedList<>();
    }
    return stores;
  }

  public void setStores(List<String> stores) {
    this.stores = stores;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(servletPaths, "servletPaths");
    notEmpty(signer, "signer");
    notEmpty(request, "request");
    notEmpty(response, "response");
    notEmpty(stores, "stores");
    notEmpty(name, "name");
  }

}
