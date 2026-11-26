// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;

/** Public, non-secret progress derived from the resources managed by Quick Start. */
public record QuickStartStatus(
    State state, boolean available, String caName, List<Step> steps, String message) {
  public enum State {
    AVAILABLE,
    IN_PROGRESS,
    COMPLETED,
    UNAVAILABLE,
    CONFLICT
  }

  public record Step(String code, boolean complete) {}
}
