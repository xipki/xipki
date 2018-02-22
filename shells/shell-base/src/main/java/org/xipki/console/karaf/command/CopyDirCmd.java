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
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.XiAction;
import org.xipki.console.karaf.completer.DirPathCompleter;
import org.xipki.console.karaf.intern.FileUtils;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "copy-dir",
    description = "copy content of the directory to destination")
@Service
public class CopyDirCmd extends XiAction {

  @Argument(index = 0, name = "source directory", required = true,
      description = "content of this directory will be copied\n(required)")
  @Completion(DirPathCompleter.class)
  private String source;

  @Argument(index = 1, name = "destination", required = true,
      description = "destination directory\n(required)")
  @Completion(DirPathCompleter.class)
  private String dest;

  @Override
  protected Object execute0() throws Exception {
    File sourceDir = new File(expandFilepath(source));
    if (!sourceDir.exists()) {
      System.err.println(source + " does not exist");
      return null;
    }

    if (!sourceDir.isDirectory()) {
      System.err.println(source + " is not a directory");
      return null;
    }

    File destDir = new File(dest);
    if (destDir.exists()) {
      if (destDir.isFile()) {
        System.err.println(dest + " is not a directory");
        return null;
      }
    } else {
      destDir.mkdirs();
    }

    FileUtils.copyDirectory(sourceDir, destDir);

    return null;
  }

}
