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
import java.util.Set;

import org.xipki.security.pkcs11.jaxb.NewObjectConfType;
import org.xipki.util.ParamUtil;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class P11NewObjectConf {

  private boolean ignoreLabel;

  private int idLength = 8;

  private Set<Long> setCertObjectAttributes;

  public P11NewObjectConf(NewObjectConfType jaxb) {
    Boolean bb = jaxb.isIgnoreLabel();
    this.ignoreLabel = (bb == null) ? false : bb.booleanValue();

    Integer ii = jaxb.getIdLength();
    this.idLength = (ii == null) ? 8 : ii.intValue();

    NewObjectConfType.CertAttributes attrs = jaxb.getCertAttributes();
    Set<Long> set = new HashSet<>();
    if (attrs != null) {
      for (String attr : attrs.getAttribute()) {
        attr = attr.toUpperCase();

        if ("CKA_START_DATE".equals(attr)) {
          set.add(PKCS11Constants.CKA_START_DATE);
        } else if ("CKA_END_DATE".equals(attr)) {
          set.add(PKCS11Constants.CKA_END_DATE);
        } else if ("CKA_SUBJECT".equals(attr)) {
          set.add(PKCS11Constants.CKA_SUBJECT);
        } else if ("CKA_ISSUER".equals(attr)) {
          set.add(PKCS11Constants.CKA_ISSUER);
        } else if ("CKA_SERIAL_NUMBER".equals(attr)) {
          set.add(PKCS11Constants.CKA_SERIAL_NUMBER);
        }
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
    this.setCertObjectAttributes =
        ParamUtil.requireNonNull("setCertObjectAttributes", setCertObjectAttributes);
  }

}
