// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class Problem {

  private String type;

  private String detail;

  private Subproblem[] subproblems;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getDetail() {
    return detail;
  }

  public void setDetail(String detail) {
    this.detail = detail;
  }

  public Subproblem[] getSubproblems() {
    return subproblems;
  }

  public void setSubproblems(Subproblem[] subproblems) {
    this.subproblems = subproblems;
  }
}
