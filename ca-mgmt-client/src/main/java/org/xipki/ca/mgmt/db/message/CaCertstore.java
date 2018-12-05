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

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaCertstore extends ValidatableConf {

  private int version;

  private int countCrls;

  private int countCerts;

  private int countRequests;

  private int countReqCerts;

  private List<ToPublish> publishQueue;

  private List<DeltaCrlCacheEntry> deltaCrlCache;

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public int getCountCrls() {
    return countCrls;
  }

  public void setCountCrls(int countCrls) {
    this.countCrls = countCrls;
  }

  public int getCountCerts() {
    return countCerts;
  }

  public void setCountCerts(int countCerts) {
    this.countCerts = countCerts;
  }

  public int getCountRequests() {
    return countRequests;
  }

  public void setCountRequests(int countRequests) {
    this.countRequests = countRequests;
  }

  public int getCountReqCerts() {
    return countReqCerts;
  }

  public void setCountReqCerts(int countReqCerts) {
    this.countReqCerts = countReqCerts;
  }

  public List<ToPublish> getPublishQueue() {
    if (publishQueue == null) {
      publishQueue = new LinkedList<>();
    }
    return publishQueue;
  }

  public void setPublishQueue(List<ToPublish> publishQueue) {
    this.publishQueue = publishQueue;
  }

  public List<DeltaCrlCacheEntry> getDeltaCrlCache() {
    if (deltaCrlCache == null) {
      deltaCrlCache = new LinkedList<>();
    }
    return deltaCrlCache;
  }

  public void setDeltaCrlCache(List<DeltaCrlCacheEntry> deltaCrlCache) {
    this.deltaCrlCache = deltaCrlCache;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(publishQueue);
    validate(deltaCrlCache);
  }

}
