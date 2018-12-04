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

package org.xipki.cmpclient.conf;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.xipki.util.conf.FileOrValue;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class CertprofileType extends ValidatableConf {

  public static class Certprofiles extends ValidatableConf {

    private boolean autoconf;

    private List<CertprofileType> profiles;

    public boolean isAutoconf() {
      return autoconf;
    }

    public void setAutoconf(boolean autoconf) {
      this.autoconf = autoconf;
    }

    public List<CertprofileType> getProfiles() {
      if (autoconf) {
        return Collections.emptyList();
      } else {
        if (profiles == null) {
          profiles = new LinkedList<>();
        }
        return profiles;
      }
    }

    public void setProfiles(List<CertprofileType> profiles) {
      this.profiles = profiles;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (!autoconf) {
        validate(profiles);
      }
    }

  }

  private String name;

  private String type;

  private FileOrValue conf;

  public String getName() {
    return name;
  }

  public void setName(String value) {
    this.name = value;
  }

  public String getType() {
    return type;
  }

  public void setType(String value) {
    this.type = value;
  }

  public FileOrValue getConf() {
    return conf;
  }

  public void setConf(FileOrValue value) {
    this.conf = value;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    validate(conf);
  }

}
