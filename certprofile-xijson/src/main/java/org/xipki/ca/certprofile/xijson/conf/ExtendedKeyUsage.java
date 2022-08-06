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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ca.api.profile.Certprofile.ExtKeyUsageControl;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.ValidatableConf;

import java.util.*;

/**
 * Extension ExtendedKeyUsage.
 *
 * @author Lijun Liao
 */

public class ExtendedKeyUsage extends ValidatableConf {

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

  public Set<ExtKeyUsageControl> toXiExtKeyUsageOptions() {
    List<Usage> usages = getUsages();
    Set<ExtKeyUsageControl> controls = new HashSet<>();

    for (Usage m : usages) {
      controls.add(new ExtKeyUsageControl(
                    new ASN1ObjectIdentifier(m.getOid()), m.isRequired()));
    }

    return Collections.unmodifiableSet(controls);
  } // method buildExtKeyUsageOptions

  public static class Usage extends DescribableOid {

    private boolean required;

    public boolean isRequired() {
      return required;
    }

    public void setRequired(boolean required) {
      this.required = required;
    }

  } // class Usage

} // class ExtendedKeyUsage
