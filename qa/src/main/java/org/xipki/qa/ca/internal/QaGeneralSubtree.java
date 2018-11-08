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

import org.xipki.ca.certprofile.xml.jaxb.GeneralSubtreeBaseType;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaGeneralSubtree {

  private final GeneralSubtreeBaseType jaxb;

  public QaGeneralSubtree(GeneralSubtreeBaseType jaxb) {
    this.jaxb = ParamUtil.requireNonNull("jaxb", jaxb);
    Integer min = jaxb.getMinimum();
    if (min != null) {
      ParamUtil.requireMin("jaxb.getMinimum()", min.intValue(), 0);
    }

    Integer max = jaxb.getMaximum();
    if (max != null) {
      ParamUtil.requireMin("jaxb.getMaximum()", max.intValue(), 0);
    }
  }

  public String getRfc822Name() {
    return jaxb.getRfc822Name();
  }

  public String getDnsName() {
    return jaxb.getDnsName();
  }

  public String getDirectoryName() {
    return jaxb.getDirectoryName();
  }

  public String getUri() {
    return jaxb.getUri();
  }

  public String getIpAddress() {
    return jaxb.getIpAddress();
  }

  public Integer getMinimum() {
    return jaxb.getMinimum();
  }

  public Integer getMaximum() {
    return jaxb.getMaximum();
  }

}
