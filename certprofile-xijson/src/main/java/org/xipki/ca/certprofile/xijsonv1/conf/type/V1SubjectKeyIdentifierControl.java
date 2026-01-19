// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.type;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.SubjectKeyIdentifierControl;

/**
 * Extension SubjectKeyIdentifierControl.
 *
 * @author Lijun Liao (xipki)
 */

public class V1SubjectKeyIdentifierControl {

  private final SubjectKeyIdentifierControl.SubjectKeyIdentifierMethod method;

  private final String hashAlgo;

  /**
   * Format
   *   - 'L':'&lt;size&gt: Use the left most size bytes.
   *   - 'R':'&lt;size&gt: Use the right most size bytes.
   * <p/>
   */
  private final String truncateMethod;

  public V1SubjectKeyIdentifierControl(
      SubjectKeyIdentifierControl.SubjectKeyIdentifierMethod method,
      String hashAlgo, String truncateMethod) {
    this.method = method;
    this.hashAlgo = hashAlgo;
    this.truncateMethod = truncateMethod;
  }

  public SubjectKeyIdentifierControl toV2() {
    SubjectKeyIdentifierControl.TruncateMethod v2TruncateMethod = null;
    Integer truncateByteSize = null;

    if (truncateMethod != null) {
      if (truncateMethod.startsWith("L") || truncateMethod.startsWith("l")) {
        v2TruncateMethod = SubjectKeyIdentifierControl.TruncateMethod.LEFT;
      } else if (truncateMethod.startsWith("R")
          || truncateMethod.startsWith("r")) {
        v2TruncateMethod = SubjectKeyIdentifierControl.TruncateMethod.RIGHT;
      } else {
        throw new IllegalArgumentException("unsupported truncateMethod '"
            + truncateMethod + "'");
      }

      truncateByteSize = Integer.parseInt(truncateMethod.substring(1));
    }

    return new SubjectKeyIdentifierControl(
        method, hashAlgo, v2TruncateMethod, truncateByteSize);
  }

  public static V1SubjectKeyIdentifierControl parse(JsonMap json)
      throws CodecException {
    return new V1SubjectKeyIdentifierControl(
        json.getEnum("method",
            SubjectKeyIdentifierControl.SubjectKeyIdentifierMethod.class),
        json.getString("hashAlgo"),
        json.getString("truncateMethod"));
  }

}
