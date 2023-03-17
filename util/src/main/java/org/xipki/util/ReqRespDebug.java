// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.util.LinkedList;
import java.util.List;

/**
 * Helper class for debug.
 *
 * @author Lijun Liao (xipki)
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
