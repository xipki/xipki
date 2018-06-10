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

package org.xipki.ca.client.impl;

import java.security.cert.X509Certificate;

import org.xipki.security.AlgorithmValidator;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

class CmpResponder {

  private final X509Certificate cert;

  private final AlgorithmValidator sigAlgoValidator;

  public CmpResponder(X509Certificate cert, AlgorithmValidator sigAlgoValidator) {
    this.cert = ParamUtil.requireNonNull("cert", cert);
    this.sigAlgoValidator = ParamUtil.requireNonNull("sigAlgoValidator", sigAlgoValidator);
  }

  public X509Certificate getCert() {
    return cert;
  }

  public AlgorithmValidator getSigAlgoValidator() {
    return sigAlgoValidator;
  }

}
