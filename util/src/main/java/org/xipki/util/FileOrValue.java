// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;

/**
 * Configuration consisting either file path or the text content.
 *
 * @author Lijun Liao (xipki)
 */

public class FileOrValue extends ValidableConf {

  private String file;

  private String value;

  public static FileOrValue ofFile(String fileName) {
    FileOrValue ret = new FileOrValue();
    ret.setFile(fileName);
    return ret;
  }

  public static FileOrValue ofValue(String value) {
    FileOrValue ret = new FileOrValue();
    ret.setValue(value);
    return ret;
  }

  public String getFile() {
    return file;
  }

  public void setFile(String file) {
    this.file = file;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  @Override
  public void validate() throws InvalidConfException {
    exactOne(file, "file", value, "value");
  }

  public String readContent() throws IOException {
    if (value != null) {
      return value;
    }

    return StringUtil.toUtf8String(IoUtil.read(IoUtil.detectPath(file)));
  }

}
