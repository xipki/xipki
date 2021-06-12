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
 * Extension SubjectInfoAccess.
 *
 * @author Lijun Liao
 */

public class SubjectInfoAccess extends ValidatableConf {

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
  public void validate()
      throws InvalidConfException {
    notEmpty(accesses, "accesses");
    validate(accesses);
  }

  public static class Access extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableOid accessMethod;

    @JSONField(ordinal = 2)
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
    public void validate()
        throws InvalidConfException {
      notNull(accessMethod, "accessMethod");
      validate(accessMethod);
      notNull(accessLocation, "accessLocation");
      validate(accessLocation);
    }

  } // class Access

} // class SubjectInfoAccess
