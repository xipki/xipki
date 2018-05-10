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

package org.xipki.console.karaf.command;

import java.io.File;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.FileUtils;
import org.xipki.console.karaf.XiAction;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "rm",
    description = "remove file or directory")
@Service
public class FileRmCmd extends XiAction {

  @Argument(index = 0, name = "file", required = true,
      description = "file or directory to be deleted\n(required)")
  @Completion(FilePathCompleter.class)
  private String targetPath;

  @Option(name = "--recursive", aliases = "-r",
      description = "remove directories and their contents recursively")
  private Boolean recursive = Boolean.FALSE;

  @Option(name = "--force", aliases = "-f",
      description = "remove files without prompt")
  private Boolean force = Boolean.FALSE;

  @Override
  protected Object execute0() throws Exception {
    File target = new File(expandFilepath(targetPath));
    if (!target.exists()) {
      return null;
    }

    if (target.isDirectory()) {
      if (!recursive) {
        println("Please use option --recursive to delete directory");
        return null;
      }

      if (force || confirm("Do you want to remove directory " + targetPath, 3)) {
        FileUtils.deleteDirectory(target);
        println("removed directory " + targetPath);
      }
    } else {
      if (force || confirm("Do you want to remove file " + targetPath, 3)) {
        target.delete();
        println("removed file " + targetPath);
      }
    }

    return null;
  }

}
