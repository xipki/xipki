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

package org.xipki.util.conf;

import java.io.IOException;

import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
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
    if (file == null && binary == null) {
      throw new InvalidConfException("file and binary may not both be null");
    }
    else if (file != null && binary != null) {
      throw new InvalidConfException("file and binary may not both be non-null");
    }
  }

  public byte[] readContent() throws IOException {
    if (binary != null) {
      return binary;
    }

    return IoUtil.read(file);
  }

}
