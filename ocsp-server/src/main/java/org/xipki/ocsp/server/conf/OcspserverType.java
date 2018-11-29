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
public class OcspserverType extends ValidatableConf {

  public static enum EmbedCertsMode {

    NONE,
    SIGNER,
    SIGNER_AND_CA;

  }

  public static enum ValidationModel {

    PKIX,
    CHAIN;

  }

  private ResponseCacheType responseCache;

  private List<ResponderType> responders;

  private List<SignerType> signers;

  private List<StoreType> stores;

  private List<DatasourceType> datasources;

  private List<RequestOptionType> requestOptions;

  private List<ResponseOptionType> responseOptions;

  private boolean master = true;

  public ResponseCacheType getResponseCache() {
    return responseCache;
  }

  public void setResponseCache(ResponseCacheType responseCache) {
    this.responseCache = responseCache;
  }

  public List<ResponderType> getResponders() {
    if (responders == null) {
      responders = new LinkedList<>();
    }
    return responders;
  }

  public void setResponders(List<ResponderType> responders) {
    this.responders = responders;
  }

  public List<SignerType> getSigners() {
    if (signers == null) {
      signers = new LinkedList<>();
    }
    return signers;
  }

  public void setSigners(List<SignerType> signers) {
    this.signers = signers;
  }

  public List<StoreType> getStores() {
    if (stores == null) {
      stores = new LinkedList<>();
    }
    return stores;
  }

  public void setStores(List<StoreType> stores) {
    this.stores = stores;
  }

  public List<DatasourceType> getDatasources() {
    if (datasources == null) {
      datasources = new LinkedList<>();
    }
    return datasources;
  }

  public void setDatasources(List<DatasourceType> datasources) {
    this.datasources = datasources;
  }

  public List<RequestOptionType> getRequestOptions() {
    if (requestOptions == null) {
      requestOptions = new LinkedList<>();
    }
    return requestOptions;
  }

  public void setRequestOptions(List<RequestOptionType> requestOptions) {
    this.requestOptions = requestOptions;
  }

  public List<ResponseOptionType> getResponseOptions() {
    if (responseOptions == null) {
      responseOptions = new LinkedList<>();
    }
    return responseOptions;
  }

  public void setResponseOptions(List<ResponseOptionType> responseOptions) {
    this.responseOptions = responseOptions;
  }

  public boolean isMaster() {
    return master;
  }

  public void setMaster(boolean master) {
    this.master = master;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(responders, "responders");
    validate(responders);

    notEmpty(signers, "signers");
    validate(signers);

    notEmpty(stores, "stores");
    validate(stores);

    validate(datasources);

    notEmpty(requestOptions, "requestOptions");
    validate(requestOptions);

    notEmpty(responseOptions, "responseOptions");
    validate(responseOptions);
  }

}
