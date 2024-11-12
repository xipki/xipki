// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.ctlog;

import java.util.List;

/**
 * Certificate transparency (CT) log client.
 *
 * @author Lijun Liao (xipki)
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

    private byte sct_version;

    private byte[] id;

    private long timestamp;

    private byte[] extensions;

    private byte[] signature;

    public byte getSct_version() {
      return sct_version;
    }

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
