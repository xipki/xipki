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

package org.xipki.dbtool;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

import liquibase.resource.FileSystemResourceAccessor;

/**
 * Class for executing Liquibase via the command line.
 *
 * @author Lijun Liao
 */
class MyFileSystemResourceAccessor extends FileSystemResourceAccessor {

  @Override
  protected void addRootPath(URL path) {
    try {
      new File(path.toURI());
    } catch (URISyntaxException e) {
      //add like normal
    } catch (IllegalArgumentException e) {
      // this line is added to avoid the IllegalArgumentException: URI is not
      // hierarchical in java 10+.
      return;
    }

    super.addRootPath(path);
  }

}
