// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.cmp;

/**
 * Protection verification result enum.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public enum ProtectionResult {

  SIGNATURE_VALID,
  SIGNATURE_INVALID,
  SIGNATURE_ALGO_FORBIDDEN,
  MAC_VALID,
  MAC_INVALID,
  MAC_ALGO_FORBIDDEN,
  SENDER_NOT_AUTHORIZED

}
