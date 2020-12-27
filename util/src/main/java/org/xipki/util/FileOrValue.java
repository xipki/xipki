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

package org.xipki.util;

import java.io.IOException;

/**
 * Configuration consisting either file path or the text content.
 *
 * @author Lijun Liao
 */

public class FileOrValue extends ValidatableConf {

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
  public void validate()
      throws InvalidConfException {
    exactOne(file, "file", value, "value");
  }

  public String readContent()
      throws IOException {
    if (value != null) {
      return value;
    }

    return new String(IoUtil.read(IoUtil.detectPath(file)), "UTF-8");
  }

}
