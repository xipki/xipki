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

package org.xipki.security.pkcs11.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 */

public class NewObjectConfType extends ValidatableConf {

  public static enum CertAttribute {
    CKA_START_DATE(PKCS11Constants.CKA_START_DATE),
    CKA_END_DATE(PKCS11Constants.CKA_END_DATE),
    CKA_SUBJECT(PKCS11Constants.CKA_SUBJECT),
    CKA_ISSUER(PKCS11Constants.CKA_ISSUER),
    CKA_SERIAL_NUMBER(PKCS11Constants.CKA_SERIAL_NUMBER);

    private final long pkcs11CkaCode;

    private CertAttribute(long pkcs11CkaCode) {
      this.pkcs11CkaCode = pkcs11CkaCode;
    }

    public long getPkcs11CkaCode() {
      return pkcs11CkaCode;
    }

  }

  private Boolean ignoreLabel;

  /**
   * If ID is generated randomly, specifies the number of bytes of an ID.
   */
  private Integer idLength;

  private List<CertAttribute> certAttributes = new LinkedList<>();

  public Boolean getIgnoreLabel() {
    return ignoreLabel;
  }

  public void setIgnoreLabel(Boolean ignoreLabel) {
    this.ignoreLabel = ignoreLabel;
  }

  public Integer getIdLength() {
    return idLength;
  }

  public void setIdLength(Integer idLength) {
    this.idLength = idLength;
  }

  public List<CertAttribute> getCertAttributes() {
    if (certAttributes == null) {
      certAttributes = new LinkedList<>();
    }
    return certAttributes;
  }

  public void setCertAttributes(List<CertAttribute> certAttributes) {
    this.certAttributes = certAttributes;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

}
