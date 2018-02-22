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

package org.xipki.console.karaf.completer;

import java.nio.file.Path;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
public class DirPathCompleter extends FileCompleter {

  @Override
  protected boolean accept(Path path) {
    return path.toFile().isDirectory() && super.accept(path);
  }

  // This method is for karaf 4.0.*
  /*
  @Override
  protected int matchFiles(String buffer, String translated, File[] files,
      List<String> candidates) {
    if (files == null) {
      return -1;
    }

    int matches = 0;

    // first pass: just count the matches
    for (File file : files) {
      if (file.isDirectory() && file.getAbsolutePath().startsWith(translated)) {
        matches++;
      }
    }
    for (File file : files) {
      if (file.isDirectory() && file.getAbsolutePath().startsWith(translated)) {
        CharSequence name =
            file.getName() + (matches == 1 && file.isDirectory() ? separator() : " ");
        candidates.add(render(file, name).toString());
      }
    }

    int index = buffer.lastIndexOf(separator());

    return index + separator().length();
  }
  */

}
