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

package org.xipki.shell;

import java.io.File;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "mkdir", description = "make directories")
@Service
public class MkdirAction extends XiAction {

  @Argument(index = 0, name = "directory", required = true, description = "directory to be created")
  @Completion(Completers.DirCompleter.class)
  private String dirName;

  @Override
  protected Object execute0() throws Exception {
    File target = new File(expandFilepath(dirName));
    if (target.exists()) {
      if (!target.isDirectory()) {
        System.err.println(dirName + " exists but is not a directory, cannot override it");
        return null;
      }
    } else {
      target.mkdirs();
    }

    return null;
  }

}
