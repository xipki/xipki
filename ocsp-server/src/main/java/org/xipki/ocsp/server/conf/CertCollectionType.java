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

package org.xipki.ocsp.server.conf;

import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class CertCollectionType extends ValidatableConf {

  private String dir;

  private CertCollectionType.Keystore keystore;

  public String getDir() {
    return dir;
  }

  public void setDir(String value) {
    this.dir = value;
  }

  public CertCollectionType.Keystore getKeystore() {
    return keystore;
  }

  public void setKeystore(CertCollectionType.Keystore value) {
    this.keystore = value;
  }

  @Override
  public void validate() throws InvalidConfException {
    exactOne(keystore, "keystore", dir, "dir");
    validate(keystore);
  }

  public static class Keystore extends ValidatableConf {

    private String type;

    private FileOrBinary keystore;

    private String password;

    public String getType() {
      return type;
    }

    public void setType(String value) {
      this.type = value;
    }

    public FileOrBinary getKeystore() {
      return keystore;
    }

    public void setKeystore(FileOrBinary value) {
      this.keystore = value;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(String value) {
      this.password = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(type, "type");
      validate(keystore);
    }

  }

}
