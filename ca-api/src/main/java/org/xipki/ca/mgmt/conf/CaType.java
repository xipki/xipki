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

import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaType extends ValidatableConf {

  private String name;

  private CaInfoType caInfo;

  private List<String> aliases;

  private List<String> profiles;

  private List<CaHasRequestorType> requestors;

  private List<CaHasUserType> users;

  private List<String> publishers;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public CaInfoType getCaInfo() {
    return caInfo;
  }

  public void setCaInfo(CaInfoType caInfo) {
    this.caInfo = caInfo;
  }

  public List<String> getAliases() {
    if (aliases == null) {
      aliases = new LinkedList<>();
    }
    return aliases;
  }

  public void setAliases(List<String> aliases) {
    this.aliases = aliases;
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

  public List<CaHasRequestorType> getRequestors() {
    if (requestors == null) {
      requestors = new LinkedList<>();
    }
    return requestors;
  }

  public void setRequestors(List<CaHasRequestorType> requestors) {
    this.requestors = requestors;
  }

  public List<CaHasUserType> getUsers() {
    if (users == null) {
      users = new LinkedList<>();
    }
    return users;
  }

  public void setUsers(List<CaHasUserType> users) {
    this.users = users;
  }

  public List<String> getPublishers() {
    if (publishers == null) {
      publishers = new LinkedList<>();
    }
    return publishers;
  }

  public void setPublishers(List<String> publishers) {
    this.publishers = publishers;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    validate(caInfo);
    validate(requestors);
    validate(users);
  }

}
