// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa;

import org.xipki.util.codec.Args;

/**
 * Single validation issue.
 *
 * @author Lijun Liao (xipki)
 */

public class ValidationIssue {

  private final String code;

  private final String description;

  private boolean failed;

  private String failureMessage;

  public ValidationIssue(String code, String description) {
    this.code = Args.notBlank(code, "code");
    this.description = Args.notBlank(description, "description");
    this.failed = false;
  }

  public boolean isFailed() {
    return failed;
  }

  public String getFailureMessage() {
    return failureMessage;
  }

  public void setFailureMessage(String failureMessage) {
    this.failureMessage = Args.notNull(failureMessage, "failureMessage");
    this.failed = true;
  }

  public String getCode() {
    return code;
  }

  public String getDescription() {
    return description;
  }

}
