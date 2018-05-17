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

package org.xipki.ca.server.mgmt.api;

import java.util.Collections;
import java.util.List;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaUris {
  private final List<String> caCertUris;
  private final List<String> ocspUris;
  private final List<String> crlUris;
  private final List<String> deltaCrlUris;

  public CaUris(List<String> caCertUris, List<String> ocspUris, List<String> crlUris,
      List<String> deltaCrlUris) {
    this.caCertUris = (caCertUris == null)
        ? Collections.emptyList() : Collections.unmodifiableList(caCertUris);
    this.ocspUris = (ocspUris == null)
        ? Collections.emptyList() : Collections.unmodifiableList(ocspUris);
    this.crlUris = (crlUris == null)
        ? Collections.emptyList() : Collections.unmodifiableList(crlUris);
    this.deltaCrlUris = (deltaCrlUris == null)
        ? Collections.emptyList() : Collections.unmodifiableList(deltaCrlUris);
  }

  public List<String> getCaCertUris() {
    return caCertUris;
  }

  public List<String> getOcspUris() {
    return ocspUris;
  }

  public List<String> getCrlUris() {
    return crlUris;
  }

  public List<String> getDeltaCrlUris() {
    return deltaCrlUris;
  }

}
