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

package org.xipki.ocsp.server.impl;

import java.util.List;

import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.Responder;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ResponderImpl implements Responder {

  private final ResponderOption responderOption;

  private final RequestOption requestOption;

  private final ResponseOption responseOption;

  private final ResponderSigner signer;

  private final List<OcspStore> stores;

  ResponderImpl(ResponderOption responderOption, RequestOption requestOption,
      ResponseOption responseOption, ResponderSigner signer, List<OcspStore> stores) {
    this.responderOption = ParamUtil.requireNonNull("responderOption", responderOption);
    this.requestOption = ParamUtil.requireNonNull("requestOption", requestOption);
    this.responseOption = ParamUtil.requireNonNull("responseOption", responseOption);
    this.signer = ParamUtil.requireNonNull("signer", signer);
    this.stores = ParamUtil.requireNonEmpty("stores", stores);
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

  public ResponderSigner getSigner() {
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
