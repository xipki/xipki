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

@Command(scope = "xi", name = "move-dir",
    description = "move content of the directory to destination")
@Service
public class MoveDirAction extends XiAction {

  @Argument(index = 0, name = "source", required = true,
      description = "content of this directory will be copied")
  @Completion(Completers.DirCompleter.class)
  private String source;

  @Argument(index = 1, name = "destination", required = true, description = "destination directory")
  @Completion(Completers.DirCompleter.class)
  private String dest;

  @Override
  protected Object execute0() throws Exception {
    source = expandFilepath(source);
    dest = expandFilepath(dest);

    File sourceDir = new File(source);
    if (!sourceDir.exists()) {
      throw new IllegalCmdParamException(source + " does not exist");
    }

    if (!sourceDir.isDirectory()) {
      throw new IllegalCmdParamException(source + " is not a directory");
    }

    File destDir = new File(dest);
    if (destDir.exists()) {
      if (destDir.isFile()) {
        throw new IllegalCmdParamException(dest + " is not a directory");
      }
    } else {
      destDir.mkdirs();
    }

    FileUtils.copyDirectory(sourceDir, destDir);
    FileUtils.deleteDirectory(sourceDir);

    return null;
  }

}
