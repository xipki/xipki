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

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class CmpcontrolType extends ValidatableConf {

  private boolean autoconf;

  private Boolean rrAkiRequired;

  public boolean isAutoconf() {
    return autoconf;
  }

  public void setAutoconf(boolean autoconf) {
    this.autoconf = autoconf;
  }

  public Boolean getRrAkiRequired() {
    return autoconf ? null : rrAkiRequired;
  }

  public void setRrAkiRequired(Boolean rrAkiRequired) {
    this.rrAkiRequired = rrAkiRequired;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

}
