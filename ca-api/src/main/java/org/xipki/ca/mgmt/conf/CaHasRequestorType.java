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

package org.xipki.ca.mgmt.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaHasRequestorType extends ValidatableConf {

  private String requestorName;

  private boolean ra;

  private List<String> permissions;

  private List<String> profiles;

  public String getRequestorName() {
    return requestorName;
  }

  public void setRequestorName(String requestorName) {
    this.requestorName = requestorName;
  }

  public boolean isRa() {
    return ra;
  }

  public void setRa(boolean ra) {
    this.ra = ra;
  }

  public List<String> getPermissions() {
    if (permissions == null) {
      permissions = new LinkedList<>();
    }
    return permissions;
  }

  public void setPermissions(List<String> permissions) {
    this.permissions = permissions;
  }

  public List<String> getProfiles() {
    if (profiles == null) {
      profiles = new LinkedList<>();
    }
    return profiles;
  }

  public void setProfiles(List<String> profiles) {
    this.profiles = profiles;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(requestorName, "requestorName");
    notEmpty(permissions, "permissions");
  }

}
