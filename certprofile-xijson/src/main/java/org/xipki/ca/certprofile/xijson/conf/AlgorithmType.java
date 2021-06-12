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

import com.alibaba.fastjson.annotation.JSONField;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import java.util.LinkedList;
import java.util.List;

/**
 * Configuration of the signature algorithm of certificate.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class AlgorithmType extends ValidatableConf {

  @JSONField(ordinal = 1)
  private List<DescribableOid> algorithms;

  @JSONField(ordinal = 2)
  private KeyParametersType parameters;

  public List<DescribableOid> getAlgorithms() {
    if (algorithms == null) {
      algorithms = new LinkedList<>();
    }
    return algorithms;
  }

  public void setAlgorithms(List<DescribableOid> algorithms) {
    this.algorithms = algorithms;
  }

  public KeyParametersType getParameters() {
    return parameters;
  }

  public void setParameters(KeyParametersType parameters) {
    this.parameters = parameters;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    notEmpty(algorithms, "algorithms");
    validate(algorithms);
    validate(parameters);
  }

}
