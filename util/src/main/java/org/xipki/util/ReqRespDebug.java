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

package org.xipki.util;

import java.util.LinkedList;
import java.util.List;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ReqRespDebug {

  public static class ReqRespPair {

    private byte[] request;

    private byte[] response;

    public byte[] getRequest() {
      return request;
    }

    public void setRequest(byte[] request) {
      this.request = request;
    }

    public byte[] getResponse() {
      return response;
    }

    public void setResponse(byte[] response) {
      this.response = response;
    }

  }

  private final List<ReqRespPair> pairs = new LinkedList<>();

  private final boolean saveRequest;

  private final boolean saveResponse;

  public ReqRespDebug(boolean saveRequest, boolean saveResponse) {
    if (!(saveRequest || saveResponse)) {
      throw new IllegalArgumentException("saveRequest and saveResponse may not be both false");
    }
    this.saveRequest = saveRequest;
    this.saveResponse = saveResponse;
  }

  public boolean saveRequest() {
    return saveRequest;
  }

  public boolean saveResponse() {
    return saveResponse;
  }

  public void add(ReqRespPair pair) {
    pairs.add(pair);
  }

  public int size() {
    return pairs.size();
  }

  public ReqRespPair get(int index) {
    return pairs.get(index);
  }

  public boolean remove(ReqRespPair pair) {
    return pairs.remove(pair);
  }

  public ReqRespPair remove(int index) {
    return pairs.remove(index);
  }

}
