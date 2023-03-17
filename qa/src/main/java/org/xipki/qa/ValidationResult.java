// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa;

import org.xipki.util.CollectionUtil;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.xipki.util.Args.notEmpty;

/**
 * Validation result consisting of failed validation issues and successful issues.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ValidationResult {

  private final List<ValidationIssue> validationIssues;

  private final List<ValidationIssue> failedValidationIssues;

  private final List<ValidationIssue> successfulValidationIssues;

  public ValidationResult(ValidationIssue validationIssues) {
    this(Collections.singletonList(validationIssues));
  }

  public ValidationResult(List<ValidationIssue> validationIssues) {
    this.validationIssues = notEmpty(validationIssues, "validationIssues");

    List<ValidationIssue> failedIssues = new LinkedList<>();
    List<ValidationIssue> successfulIssues = new LinkedList<>();
    for (ValidationIssue issue : validationIssues) {
      if (issue.isFailed()) {
        failedIssues.add(issue);
      } else {
        successfulIssues.add(issue);
      }
    }

    this.failedValidationIssues = failedIssues;
    this.successfulValidationIssues = successfulIssues;
  }

  public boolean isAllSuccessful() {
    return CollectionUtil.isEmpty(failedValidationIssues);
  }

  public List<ValidationIssue> getValidationIssues() {
    return validationIssues;
  }

  public List<ValidationIssue> getFailedValidationIssues() {
    return failedValidationIssues;
  }

  public List<ValidationIssue> getSuccessfulValidationIssues() {
    return successfulValidationIssues;
  }

}
