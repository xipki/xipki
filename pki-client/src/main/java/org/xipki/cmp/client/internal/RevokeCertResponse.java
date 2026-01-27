// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * Response of revoking certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class RevokeCertResponse {

  private List<ResultEntry> resultEntries;

  List<ResultEntry> getResultEntries() {
    return resultEntries;
  }

  void addResultEntry(ResultEntry resultEntry) {
    Args.notNull(resultEntry, "resultEntry");
    if (!(resultEntry instanceof ResultEntry.RevokeCert
        || resultEntry instanceof ResultEntry.Error)) {
      throw new IllegalArgumentException("unaccepted parameter of class "
          + resultEntry.getClass().getName());
    }

    if (resultEntries == null) {
      resultEntries = new ArrayList<>(1);
    }

    resultEntries.add(resultEntry);
  }

}
