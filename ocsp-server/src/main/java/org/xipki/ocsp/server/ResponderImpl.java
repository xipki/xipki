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

package org.xipki.ocsp.server;

import java.util.List;

import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.Responder;
import org.xipki.ocsp.server.OcspServerConf.ResponseOption;
import org.xipki.util.Args;

/**
 * Implementation of {@link Responder}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ResponderImpl implements Responder {

  private final ResponderOption responderOption;

  private final RequestOption requestOption;

  private final ResponseOption responseOption;

  private final ResponseSigner signer;

  private final List<OcspStore> stores;

  ResponderImpl(ResponderOption responderOption, RequestOption requestOption,
      ResponseOption responseOption, ResponseSigner signer, List<OcspStore> stores) {
    this.responderOption = Args.notNull(responderOption, "responderOption");
    this.requestOption = Args.notNull(requestOption, "requestOption");
    this.responseOption = Args.notNull(responseOption, "responseOption");
    this.signer = Args.notNull(signer, "signer");
    this.stores = Args.notEmpty(stores, "stores");
  }

  public ResponderOption getResponderOption() {
    return responderOption;
  }

  public RequestOption getRequestOption() {
    return requestOption;
  }

  public ResponseOption getResponseOption() {
    return responseOption;
  }

  public ResponseSigner getSigner() {
    return signer;
  }

  public List<OcspStore> getStores() {
    return stores;
  }

  @Override
  public int getMaxRequestSize() {
    return requestOption.getMaxRequestSize();
  }

  @Override
  public boolean supportsHttpGet() {
    return requestOption.supportsHttpGet();
  }

  @Override
  public Long getCacheMaxAge() {
    return responseOption.getCacheMaxAge();
  }

}
