/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.ValidatableConf;

import java.util.*;

/**
 * Extension KeyUsage.
 *
 * @author Lijun Liao
 */

public class KeyUsage extends ValidatableConf {

  private List<Usage> usages;

  public List<Usage> getUsages() {
    if (usages == null) {
      usages = new LinkedList<>();
    }
    return usages;
  }

  public void setUsages(List<Usage> usages) {
    this.usages = usages;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    notEmpty(usages, "usages");
    validate(usages);
  }

  public Set<KeyUsageControl> toXiKeyUsageOptions() {
    List<Usage> usages = getUsages();
    Set<KeyUsageControl> controls = new HashSet<>();

    for (Usage m : usages) {
      controls.add(new KeyUsageControl(m.getValue(), m.isRequired()));
    }

    return Collections.unmodifiableSet(controls);
  } // method toXiKeyUsageOptions

  public static class Usage extends ValidatableConf {

    private String value;

    private boolean required;

    public String getValue() {
      return value;
    }

    public void setValue(String value) {
      this.value = value;
    }

    public boolean isRequired() {
      return required;
    }

    public void setRequired(boolean required) {
      this.required = required;
    }

    @Override
    public void validate()
        throws InvalidConfException {
    }

  } // class Usage

} // class KeyUsage
