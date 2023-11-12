// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Extension TlsFeature.
 *
 * @author Lijun Liao (xipki)
 */

public class TlsFeature extends ValidableConf {

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
  public void validate() throws InvalidConfException {
    notEmpty(features, "features");
    validate(features);
  }

} // class TlsFeature
