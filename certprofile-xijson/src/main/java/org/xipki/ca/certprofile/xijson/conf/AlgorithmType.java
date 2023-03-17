// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Configuration of the signature algorithm of certificate.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class AlgorithmType extends ValidatableConf {

  private List<DescribableOid> algorithms;

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
  public void validate() throws InvalidConfException {
    notEmpty(algorithms, "algorithms");
    validate(algorithms);
    validate(parameters);
  }

}
