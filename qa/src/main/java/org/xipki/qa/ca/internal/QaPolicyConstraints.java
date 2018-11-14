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

package org.xipki.qa.ca.internal;

import org.xipki.ca.certprofile.xml.jaxb.PolicyConstraints;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaPolicyConstraints extends QaExtension {

  private final Integer requireExplicitPolicy;

  private final Integer inhibitPolicyMapping;

  public QaPolicyConstraints(PolicyConstraints jaxb) {
    Args.notNull(jaxb, "jaxb");
    if (jaxb.getRequireExplicitPolicy() == null && jaxb.getInhibitPolicyMapping() == null) {
      throw new IllegalArgumentException(
          "at least one of requireExplicitPolicy and inhibitPolicyMapping must be set");
    }

    this.requireExplicitPolicy = jaxb.getRequireExplicitPolicy();
    this.inhibitPolicyMapping = jaxb.getInhibitPolicyMapping();
  }

  public Integer getRequireExplicitPolicy() {
    return requireExplicitPolicy;
  }

  public Integer getInhibitPolicyMapping() {
    return inhibitPolicyMapping;
  }

}
