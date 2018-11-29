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

package org.xipki.ca.mgmt.db.message;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Caconf extends ValidatableConf {

  private int version;

  private List<Signer> signers;

  private List<IdNameTypeConf> requestors;

  private List<IdNameTypeConf> publishers;

  private List<IdNameTypeConf> profiles;

  private List<Ca> cas;

  private List<Caalias> caaliases;

  private List<User> users;

  private List<CaHasEntry.CaHasRequestor> caHasRequestors;

  private List<CaHasEntry.CaHasPublisher> caHasPublishers;

  private List<CaHasEntry.CaHasProfile> caHasProfiles;

  private List<CaHasEntry.CaHasUser> caHasUsers;

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public List<Signer> getSigners() {
    if (signers == null) {
      signers = new LinkedList<>();
    }
    return signers;
  }

  public void setSigners(List<Signer> signers) {
    this.signers = signers;
  }

  public List<IdNameTypeConf> getRequestors() {
    if (requestors == null) {
      requestors = new LinkedList<>();
    }
    return requestors;
  }

  public void setRequestors(List<IdNameTypeConf> requestors) {
    this.requestors = requestors;
  }

  public List<IdNameTypeConf> getPublishers() {
    if (publishers == null) {
      publishers = new LinkedList<>();
    }
    return publishers;
  }

  public void setPublishers(List<IdNameTypeConf> publishers) {
    this.publishers = publishers;
  }

  public List<IdNameTypeConf> getProfiles() {
    if (profiles == null) {
      profiles = new LinkedList<>();
    }
    return profiles;
  }

  public void setProfiles(List<IdNameTypeConf> profiles) {
    this.profiles = profiles;
  }

  public List<Ca> getCas() {
    if (cas == null) {
      cas = new LinkedList<>();
    }
    return cas;
  }

  public void setCas(List<Ca> cas) {
    this.cas = cas;
  }

  public List<Caalias> getCaaliases() {
    if (caaliases == null) {
      caaliases = new LinkedList<>();
    }
    return caaliases;
  }

  public void setCaaliases(List<Caalias> caaliases) {
    this.caaliases = caaliases;
  }

  public List<User> getUsers() {
    if (users == null) {
      users = new LinkedList<>();
    }
    return users;
  }

  public void setUsers(List<User> users) {
    this.users = users;
  }

  public List<CaHasEntry.CaHasRequestor> getCaHasRequestors() {
    if (caHasRequestors == null) {
      caHasRequestors = new LinkedList<>();
    }
    return caHasRequestors;
  }

  public void setCaHasRequestors(List<CaHasEntry.CaHasRequestor> caHasRequestors) {
    this.caHasRequestors = caHasRequestors;
  }

  public List<CaHasEntry.CaHasPublisher> getCaHasPublishers() {
    if (caHasPublishers == null) {
      caHasPublishers = new LinkedList<>();
    }
    return caHasPublishers;
  }

  public void setCaHasPublishers(List<CaHasEntry.CaHasPublisher> caHasPublishers) {
    this.caHasPublishers = caHasPublishers;
  }

  public List<CaHasEntry.CaHasProfile> getCaHasProfiles() {
    if (caHasProfiles == null) {
      caHasProfiles = new LinkedList<>();
    }
    return caHasProfiles;
  }

  public void setCaHasProfiles(List<CaHasEntry.CaHasProfile> caHasProfiles) {
    this.caHasProfiles = caHasProfiles;
  }

  public List<CaHasEntry.CaHasUser> getCaHasUsers() {
    if (caHasUsers == null) {
      caHasUsers = new LinkedList<>();
    }
    return caHasUsers;
  }

  public void setCaHasUsers(List<CaHasEntry.CaHasUser> caHasUsers) {
    this.caHasUsers = caHasUsers;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(signers);
    validate(requestors);
    validate(publishers);
    validate(profiles);
    validate(cas);
    validate(caaliases);
    validate(users);
    validate(caHasRequestors);
    validate(caHasPublishers);
    validate(caHasProfiles);
  }

}
