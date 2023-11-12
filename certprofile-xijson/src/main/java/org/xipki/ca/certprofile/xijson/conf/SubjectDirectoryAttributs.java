// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Extension SubjectDirectoryAttributs.
 *
 * @author Lijun Liao (xipki)
 */

public class SubjectDirectoryAttributs extends ValidableConf {

  private List<DescribableOid> types;

  public List<DescribableOid> getTypes() {
    if (types == null) {
      types = new LinkedList<>();
    }
    return types;
  }

  public void setTypes(List<DescribableOid> types) {
    this.types = types;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(types, "types");
    validate(types);
  }

} // class SubjectDirectoryAttributs
