// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.Responder;
import org.xipki.ocsp.server.OcspServerConf.ResponseOption;

import java.util.List;

import static org.xipki.util.Args.notEmpty;
import static org.xipki.util.Args.notNull;

/**
 * Implementation of {@link Responder}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ResponderImpl implements Responder {

  private final ResponderOption responderOption;

  private final RequestOption requestOption;

  private final ResponseOption responseOption;

  private final ResponseSigner signer;

  private final List<OcspStore> stores;

  ResponderImpl(
      ResponderOption responderOption, RequestOption requestOption,
      ResponseOption responseOption, ResponseSigner signer, List<OcspStore> stores) {
    this.responderOption = notNull(responderOption, "responderOption");
    this.requestOption = notNull(requestOption, "requestOption");
    this.responseOption = notNull(responseOption, "responseOption");
    this.signer = notNull(signer, "signer");
    this.stores = notEmpty(stores, "stores");
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
