// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.server.OcspServerConf.ResponseOption;
import org.xipki.util.Args;

import java.util.List;

/**
 * Implementation of {@link Responder}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class Responder {

  private final ResponderOption responderOption;

  private final RequestOption requestOption;

  private final ResponseOption responseOption;

  private final ResponseSigner signer;

  private final List<OcspStore> stores;

  Responder(
      ResponderOption responderOption, RequestOption requestOption,
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

  public int getMaxRequestSize() {
    return requestOption.getMaxRequestSize();
  }

  public boolean supportsHttpGet() {
    return requestOption.supportsHttpGet();
  }

  public Long getCacheMaxAge() {
    return responseOption.getCacheMaxAge();
  }

}
