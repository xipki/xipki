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

package org.xipki.ca.api;

import java.util.Collections;
import java.util.List;

import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaUris {

  public static final CaUris EMPTY_INSTANCE = new CaUris(null, null, null, null);

  private static final String NAME_CACERT_URIS = "cacert.uris";

  private static final String NAME_OCSP_URIS = "ocsp.uris";

  private static final String NAME_CRL_URIS = "crl.uris";

  private static final String NAME_DELTACRL_URIS = "deltacrl.uris";

  private final List<String> cacertUris;
  private final List<String> ocspUris;
  private final List<String> crlUris;
  private final List<String> deltaCrlUris;

  public CaUris(List<String> cacertUris, List<String> ocspUris, List<String> crlUris,
      List<String> deltaCrlUris) {
    this.cacertUris = (cacertUris == null) ? null : Collections.unmodifiableList(cacertUris);
    this.ocspUris = (ocspUris == null) ? null : Collections.unmodifiableList(ocspUris);
    this.crlUris = (crlUris == null) ? null : Collections.unmodifiableList(crlUris);
    this.deltaCrlUris = (deltaCrlUris == null) ? null : Collections.unmodifiableList(deltaCrlUris);
  }

  public List<String> getCacertUris() {
    return cacertUris;
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

  public boolean equals(Object obj) {
    if (! (obj instanceof CaUris)) {
      return false;
    }

    CaUris other = (CaUris) obj;
    return CompareUtil.equalsObject(cacertUris, other.cacertUris)
        && CompareUtil.equalsObject(ocspUris, other.ocspUris)
        && CompareUtil.equalsObject(crlUris, other.crlUris)
        && CompareUtil.equalsObject(deltaCrlUris, other.deltaCrlUris);
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("CA URIs:");
    sb.append("\n  CACert URIs:").append(formatUris(cacertUris));
    sb.append("\n  OCSP URIs:").append(formatUris(ocspUris));
    sb.append("\n  CRL URIs:").append(formatUris(crlUris));
    sb.append("\n  DeltaCRL URIs:").append(formatUris(deltaCrlUris));
    return sb.toString();
  }

  private static String formatUris(List<String> uris) {
    if (CollectionUtil.isEmpty(uris)) {
      return "";
    }
    StringBuilder sb = new StringBuilder();
    for (String uri : uris) {
      sb.append("\n    ").append(uri);
    }
    return sb.toString();
  }

  public static CaUris decode(String encoded) {
    ConfPairs pairs = new ConfPairs(encoded);
    return new CaUris(
        StringUtil.split(pairs.value(NAME_CACERT_URIS), "|"),
        StringUtil.split(pairs.value(NAME_OCSP_URIS), "|"),
        StringUtil.split(pairs.value(NAME_CRL_URIS), "|"),
        StringUtil.split(pairs.value(NAME_DELTACRL_URIS), "|"));
  }

  public String getEncoded() {
    ConfPairs pairs = new ConfPairs();
    if (!CollectionUtil.isEmpty(cacertUris)) {
      String str = StringUtil.collectionAsString(cacertUris, "|");
      pairs.putPair(NAME_CACERT_URIS, str);
    }

    if (!CollectionUtil.isEmpty(ocspUris)) {
      String str = StringUtil.collectionAsString(ocspUris, "|");
      pairs.putPair(NAME_OCSP_URIS, str);
    }

    if (!CollectionUtil.isEmpty(crlUris)) {
      String str = StringUtil.collectionAsString(crlUris, "|");
      pairs.putPair(NAME_CRL_URIS, str);
    }

    if (!CollectionUtil.isEmpty(deltaCrlUris)) {
      String str = StringUtil.collectionAsString(deltaCrlUris, "|");
      pairs.putPair(NAME_DELTACRL_URIS, str);
    }

    return pairs.getEncoded();
  }

}
