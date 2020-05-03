/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.ctlog;

import java.util.List;

/**
 * Certificate transparency (CT) log client.
 *
 * @author Lijun Liao
 */
public class CtLogMessages {

  // Do not change the variable name, and the get- and set-methods.
  public static class AddPreChainRequest {
    private List<byte[]> chain;

    public List<byte[]> getChain() {
      return chain;
    }

    public void setChain(List<byte[]> chain) {
      this.chain = chain;
    }

  } // class AddPreChainRequest

  // Do not change the variable name, and the get- and set-methods.
  public static class AddPreChainResponse {

    // CHECKSTYLE:SKIP
    private byte sct_version;

    private byte[] id;

    private long timestamp;

    private byte[] extensions;

    private byte[] signature;

    public byte getSct_version() {
      return sct_version;
    }

    // CHECKSTYLE:SKIP
    public void setSct_version(byte sct_version) {
      this.sct_version = sct_version;
    }

    public byte[] getId() {
      return id;
    }

    public void setId(byte[] id) {
      this.id = id;
    }

    public long getTimestamp() {
      return timestamp;
    }

    public void setTimestamp(long timestamp) {
      this.timestamp = timestamp;
    }

    public byte[] getExtensions() {
      return extensions;
    }

    public void setExtensions(byte[] extensions) {
      this.extensions = extensions;
    }

    public byte[] getSignature() {
      return signature;
    }

    public void setSignature(byte[] signature) {
      this.signature = signature;
    }

  } // class AddPreChainResponse

}
