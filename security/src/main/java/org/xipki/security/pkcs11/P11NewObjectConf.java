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

package org.xipki.security.pkcs11;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class P11NewObjectConf {

  private boolean ignoreLabel;

  private int idLength = 8;

  private Set<Long> setCertObjectAttributes;

  public P11NewObjectConf(Pkcs11conf.NewObjectConf conf) {
    Boolean bb = conf.getIgnoreLabel();
    this.ignoreLabel = (bb == null) ? false : bb.booleanValue();

    Integer ii = conf.getIdLength();
    this.idLength = (ii == null) ? 8 : ii.intValue();

    List<Pkcs11conf.NewObjectConf.CertAttribute> attrs = conf.getCertAttributes();
    Set<Long> set = new HashSet<>();
    if (attrs != null) {
      for (Pkcs11conf.NewObjectConf.CertAttribute attr : attrs) {
        set.add(attr.getPkcs11CkaCode());
      }
    }
    this.setCertObjectAttributes = Collections.unmodifiableSet(set);
  }

  public P11NewObjectConf() {
    this.setCertObjectAttributes = Collections.emptySet();
  }

  public boolean isIgnoreLabel() {
    return ignoreLabel;
  }

  public void setIgnoreLabel(boolean ignoreLabel) {
    this.ignoreLabel = ignoreLabel;
  }

  public int getIdLength() {
    return idLength;
  }

  public void setIdLength(int idLength) {
    this.idLength = idLength;
  }

  public Set<Long> getSetCertObjectAttributes() {
    return setCertObjectAttributes;
  }

  public void setSetCertObjectAttributes(Set<Long> setCertObjectAttributes) {
    this.setCertObjectAttributes = Args.notNull(setCertObjectAttributes, "setCertObjectAttributes");
  }

}
