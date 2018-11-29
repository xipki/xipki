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

public class Request extends IdentifidDbObject {

  public static class Requests extends ValidatableConf {

    private List<Request> requests;

    public List<Request> getRequests() {
      if (requests == null) {
        requests = new LinkedList<>();
      }
      return requests;
    }

    public void setRequests(List<Request> requests) {
      this.requests = requests;
    }

    public void add(Request request) {
      if (requests == null) {
        requests = new LinkedList<>();
      }
      requests.add(request);
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(requests);
    }

  }

  private Long update;

  private String file;

  public Long getUpdate() {
    return update;
  }

  public void setUpdate(Long update) {
    this.update = update;
  }

  public String getFile() {
    return file;
  }

  public void setFile(String file) {
    this.file = file;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    notNull(update, "update");
    notEmpty(file, "file");
  }

}
