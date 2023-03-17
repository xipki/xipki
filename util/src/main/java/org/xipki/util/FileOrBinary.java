// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;

/**
 * Configuration consisting either file path or the binary content.
 *
 * @author Lijun Liao (xipki)
 */

public class FileOrBinary extends ValidatableConf {

  private String file;

  private byte[] binary;

  public static FileOrBinary ofFile(String fileName) {
    FileOrBinary ret = new FileOrBinary();
    ret.setFile(fileName);
    return ret;
  }

  public static FileOrBinary ofBinary(byte[] binary) {
    FileOrBinary ret = new FileOrBinary();
    ret.setBinary(binary);
    return ret;
  }

  public String getFile() {
    return file;
  }

  public void setFile(String file) {
    this.file = file;
  }

  public byte[] getBinary() {
    return binary;
  }

  public void setBinary(byte[] binary) {
    this.binary = binary;
  }

  @Override
  public void validate() throws InvalidConfException {
    exactOne(file, "file", binary, "binary");
  }

  public byte[] readContent() throws IOException {
    if (binary != null) {
      return binary;
    }

    return IoUtil.read(IoUtil.detectPath(file));
  }

}
