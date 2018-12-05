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

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaconfType extends ValidatableConf {

  /**
   * Specify the base directory for relative path specified in this
   * configuration file. Use 'APP_DIR' for application working directory.
   * Default is the directory where this configuration file locates. Will be
   * ignored if this configuration file is contained in a ZIP file.
   */
  private String basedir;

  /**
   * The element name specifies the property name, the the element
   * value specifies the property value. The property propname can be referenced by
   * ${propname}.

   * Property baseDir is reserved which points to the parent directory
   * of the configuration file
   */
  private Map<String, String> properties;

  private List<SignerType> signers;

  private List<RequestorType> requestors;

  private List<NameTypeConf> publishers;

  private List<NameTypeConf> profiles;

  private List<CaType> cas;

  private List<UserType> users;

  public String getBasedir() {
    return basedir;
  }

  public void setBasedir(String basedir) {
    this.basedir = basedir;
  }

  public Map<String, String> getProperties() {
    if (properties == null) {
      properties = new HashMap<>();
    }
    return properties;
  }

  public void setProperties(Map<String, String> properties) {
    this.properties = properties;
  }

  public List<SignerType> getSigners() {
    if (signers == null) {
      signers = new LinkedList<>();
    }
    return signers;
  }

  public void setSigners(List<SignerType> signers) {
    this.signers = signers;
  }

  public List<RequestorType> getRequestors() {
    if (requestors == null) {
      requestors = new LinkedList<>();
    }
    return requestors;
  }

  public void setRequestors(List<RequestorType> requestors) {
    this.requestors = requestors;
  }

  public List<NameTypeConf> getPublishers() {
    if (publishers == null) {
      publishers = new LinkedList<>();
    }
    return publishers;
  }

  public void setPublishers(List<NameTypeConf> publishers) {
    this.publishers = publishers;
  }

  public List<NameTypeConf> getProfiles() {
    if (profiles == null) {
      profiles = new LinkedList<>();
    }
    return profiles;
  }

  public void setProfiles(List<NameTypeConf> profiles) {
    this.profiles = profiles;
  }

  public List<CaType> getCas() {
    if (cas == null) {
      cas = new LinkedList<>();
    }
    return cas;
  }

  public void setCas(List<CaType> cas) {
    this.cas = cas;
  }

  public List<UserType> getUsers() {
    if (users == null) {
      users = new LinkedList<>();
    }
    return users;
  }

  public void setUsers(List<UserType> users) {
    this.users = users;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(signers);
    validate(requestors);
    validate(publishers);
    validate(profiles);
    validate(cas);
    validate(users);
  }

}
