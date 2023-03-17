// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.StringUtil;

import java.util.Collections;
import java.util.List;

/**
 * CA URIs.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaUris {

  public static final CaUris EMPTY_INSTANCE = new CaUris(null, null, null, null);

  public static final String NAME_CACERT_URIS = "cacert.uris";

  public static final String NAME_OCSP_URIS = "ocsp.uris";

  public static final String NAME_CRL_URIS = "crl.uris";

  public static final String NAME_DELTACRL_URIS = "deltacrl.uris";

  private List<String> cacertUris;
  private List<String> ocspUris;
  private List<String> crlUris;
  private List<String> deltaCrlUris;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CaUris() {
  }

  public CaUris(List<String> cacertUris, List<String> ocspUris, List<String> crlUris, List<String> deltaCrlUris) {
    this.cacertUris = (cacertUris == null) ? null : Collections.unmodifiableList(cacertUris);
    this.ocspUris = (ocspUris == null) ? null : Collections.unmodifiableList(ocspUris);
    this.crlUris = (crlUris == null) ? null : Collections.unmodifiableList(crlUris);
    this.deltaCrlUris = (deltaCrlUris == null) ? null : Collections.unmodifiableList(deltaCrlUris);
  } // constructor

  public void setCacertUris(List<String> cacertUris) {
    this.cacertUris = (cacertUris == null) ? null : Collections.unmodifiableList(cacertUris);
  }

  public List<String> getCacertUris() {
    return cacertUris;
  }

  public void setOcspUris(List<String> ocspUris) {
    this.ocspUris = (ocspUris == null) ? null : Collections.unmodifiableList(ocspUris);
  }

  public List<String> getOcspUris() {
    return ocspUris;
  }

  public void setCrlUris(List<String> crlUris) {
    this.crlUris = (crlUris == null) ? null : Collections.unmodifiableList(crlUris);
  }

  public List<String> getCrlUris() {
    return crlUris;
  }

  public void setDeltaCrlUris(List<String> deltaCrlUris) {
    this.deltaCrlUris = (deltaCrlUris == null) ? null : Collections.unmodifiableList(deltaCrlUris);
  }

  public List<String> getDeltaCrlUris() {
    return deltaCrlUris;
  }

  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (! (obj instanceof CaUris)) {
      return false;
    }

    CaUris other = (CaUris) obj;
    return CompareUtil.equalsObject(cacertUris, other.cacertUris)
        && CompareUtil.equalsObject(ocspUris, other.ocspUris)
        && CompareUtil.equalsObject(crlUris, other.crlUris)
        && CompareUtil.equalsObject(deltaCrlUris, other.deltaCrlUris);
  } // method equals

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public String toString() {
    return "CA URIs:" +
        "\n  CACert URIs:" + formatUris(cacertUris) +
        "\n  OCSP URIs:" + formatUris(ocspUris) +
        "\n  CRL URIs:" + formatUris(crlUris) +
        "\n  DeltaCRL URIs:" + formatUris(deltaCrlUris);
  } // method toString

  private static String formatUris(List<String> uris) {
    if (CollectionUtil.isEmpty(uris)) {
      return "";
    }
    StringBuilder sb = new StringBuilder();
    for (String uri : uris) {
      sb.append("\n    ").append(uri);
    }
    return sb.toString();
  } // method formatUris

  public static CaUris decode(String encoded) {
    ConfPairs pairs = new ConfPairs(encoded);
    return new CaUris(
        StringUtil.split(pairs.value(NAME_CACERT_URIS), "|"),
        StringUtil.split(pairs.value(NAME_OCSP_URIS), "|"),
        StringUtil.split(pairs.value(NAME_CRL_URIS), "|"),
        StringUtil.split(pairs.value(NAME_DELTACRL_URIS), "|"));
  } // method decode

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
  } // method getEncoded

}
