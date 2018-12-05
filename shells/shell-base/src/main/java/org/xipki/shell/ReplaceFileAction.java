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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "replace", description = "replace text in file")
@Service
public class ReplaceFileAction extends XiAction {

  @Argument(index = 0, name = "file", required = true, description = "file")
  @Completion(FileCompleter.class)
  private String source;

  @Option(name = "--old", required = true, description = "text to be replaced")
  private String oldText;

  @Option(name = "--new", required = true, description = "next text")
  private String newText;

  @Override
  protected Object execute0() throws Exception {
    File sourceFile = new File(expandFilepath(source));
    if (!sourceFile.exists()) {
      System.err.println(source + " does not exist");
      return null;
    }

    if (!sourceFile.isFile()) {
      System.err.println(source + " is not a file");
      return null;
    }

    Args.notBlank(oldText, "oldText");
    replaceFile(sourceFile, oldText, newText);

    return null;
  }

  private void replaceFile(File file, String oldText, String newText) throws Exception {
    BufferedReader reader = Files.newBufferedReader(file.toPath());
    ByteArrayOutputStream writer = new ByteArrayOutputStream();

    boolean changed = false;
    try {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.contains(oldText)) {
          changed = true;
          writer.write(line.replace(oldText, newText).getBytes());
        } else {
          writer.write(line.getBytes());
        }
        writer.write('\n');
      }
    } finally {
      writer.close();
      reader.close();
    }

    if (changed) {
      File newFile = new File(file.getPath() + "-new");
      byte[] newBytes = writer.toByteArray();
      IoUtil.save(file, newBytes);
      newFile.renameTo(file);
    }
  }

}
