// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Single validation issue.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ValidationIssue {

  private final String code;

  private final String description;

  private boolean failed;

  private String failureMessage;

  public ValidationIssue(String code, String description) {
    this.code = notBlank(code, "code");
    this.description = notBlank(description, "description");
    this.failed = false;
  }

  public boolean isFailed() {
    return failed;
  }

  public String getFailureMessage() {
    return failureMessage;
  }

  public void setFailureMessage(String failureMessage) {
    this.failureMessage = notNull(failureMessage, "failureMessage");
    this.failed = true;
  }

  public String getCode() {
    return code;
  }

  public String getDescription() {
    return description;
  }

}
