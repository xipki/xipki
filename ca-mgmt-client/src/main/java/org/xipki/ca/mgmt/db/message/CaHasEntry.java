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

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public abstract class CaHasEntry extends ValidatableConf {

  public static class CaHasPublisher extends CaHasEntry {

    private int publisherId;

    public int getPublisherId() {
      return publisherId;
    }

    public void setPublisherId(int publisherId) {
      this.publisherId = publisherId;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  }

  public static class CaHasProfile extends CaHasEntry {

    private int profileId;

    public int getProfileId() {
      return profileId;
    }

    public void setProfileId(int profileId) {
      this.profileId = profileId;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  }

  public static class CaHasRequestor extends CaHasEntry {

    private int requestorId;

    private int ra;

    private int permission;

    private String profiles;

    public int getRequestorId() {
      return requestorId;
    }

    public void setRequestorId(int requestorId) {
      this.requestorId = requestorId;
    }

    public int getRa() {
      return ra;
    }

    public void setRa(int ra) {
      this.ra = ra;
    }

    public int getPermission() {
      return permission;
    }

    public void setPermission(int permission) {
      this.permission = permission;
    }

    public String getProfiles() {
      return profiles;
    }

    public void setProfiles(String profiles) {
      this.profiles = profiles;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  }

  public static class CaHasUser extends CaHasEntry {

    private int id;

    private int userId;

    private int active;

    private int permission;

    private String profiles;

    public int getId() {
      return id;
    }

    public void setId(int id) {
      this.id = id;
    }

    public int getUserId() {
      return userId;
    }

    public void setUserId(int userId) {
      this.userId = userId;
    }

    public int getActive() {
      return active;
    }

    public void setActive(int active) {
      this.active = active;
    }

    public int getPermission() {
      return permission;
    }

    public void setPermission(int permission) {
      this.permission = permission;
    }

    public String getProfiles() {
      return profiles;
    }

    public void setProfiles(String profiles) {
      this.profiles = profiles;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  }

  private int caId;

  public int getCaId() {
    return caId;
  }

  public void setCaId(int caId) {
    this.caId = caId;
  }

}
