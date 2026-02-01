// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.server.OcspServerConf.ResponseOption;
import org.xipki.util.codec.Args;

import java.util.List;

/**
 * Implementation of {@link Responder}.
 *
 * @author Lijun Liao (xipki)
 */

public class Responder {

  private final ResponderOption responderOption;

  private final RequestOption requestOption;

  private final ResponseOption responseOption;

  private final ResponseSigner signer;

  private final List<OcspStore> stores;

  Responder(
      ResponderOption responderOption, RequestOption requestOption,
      ResponseOption responseOption, ResponseSigner signer,
      List<OcspStore> stores) {
    this.responderOption = Args.notNull(responderOption, "responderOption");
    this.requestOption = Args.notNull(requestOption, "requestOption");
    this.responseOption = Args.notNull(responseOption, "responseOption");
    this.signer = Args.notNull(signer, "signer");
    this.stores = Args.notEmpty(stores, "stores");
  }

  ResponderOption responderOption() {
    return responderOption;
  }

  public RequestOption requestOption() {
    return requestOption;
  }

  public ResponseOption responseOption() {
    return responseOption;
  }

  ResponseSigner signer() {
    return signer;
  }

  public List<OcspStore> stores() {
    return stores;
  }

  public int maxRequestSize() {
    return requestOption.maxRequestSize();
  }

  public boolean supportsHttpGet() {
    return requestOption.supportsHttpGet();
  }

  public Long cacheMaxAge() {
    return responseOption.cacheMaxAge();
  }

}
