// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.GeneralNameType;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Extension SubjectInfoAccess.
 *
 * @author Lijun Liao (xipki)
 */

public class SubjectInfoAccess extends ValidableConf {

  private List<Access> accesses;

  public List<Access> getAccesses() {
    if (accesses == null) {
      accesses = new LinkedList<>();
    }
    return accesses;
  }

  public void setAccesses(List<Access> accesses) {
    this.accesses = accesses;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(accesses, "accesses");
    validate(accesses);
  }

  public static class Access extends ValidableConf {

    private DescribableOid accessMethod;

    private GeneralNameType accessLocation;

    public DescribableOid getAccessMethod() {
      return accessMethod;
    }

    public void setAccessMethod(DescribableOid accessMethod) {
      this.accessMethod = accessMethod;
    }

    public GeneralNameType getAccessLocation() {
      return accessLocation;
    }

    public void setAccessLocation(GeneralNameType accessLocation) {
      this.accessLocation = accessLocation;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(accessMethod, "accessMethod");
      notNull(accessLocation, "accessLocation");
      validate(accessMethod, accessLocation);
    }

  } // class Access

} // class SubjectInfoAccess
