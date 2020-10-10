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

import java.util.LinkedList;
import java.util.List;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * Extension TlsFeature.
 *
 * @author Lijun Liao
 */

public class TlsFeature extends ValidatableConf {

  private List<DescribableInt> features;

  public List<DescribableInt> getFeatures() {
    if (features == null) {
      features = new LinkedList<>();
    }
    return features;
  }

  public void setFeatures(List<DescribableInt> features) {
    this.features = features;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    notEmpty(features, "features");
    validate(features);
  }

} // class TlsFeature
