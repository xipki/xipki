/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.console.karaf;

import java.io.File;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 */

public abstract class PathCompleter
{
    protected abstract boolean isDirOnly();

    private static final boolean OS_IS_WINDOWS = Configuration.isWindows();

    public int complete(String buffer, final int cursor, final List<String> candidates)
    {
        if(candidates == null)
        {
            throw new IllegalArgumentException("candidates could not be null");
        }

        if (buffer == null)
        {
            buffer = "";
        }

        if (OS_IS_WINDOWS)
        {
            buffer = buffer.replace('/', '\\');
        }

        String translated = buffer;

        File homeDir = getUserHome();

        // Special character: ~ maps to the user's home directory
        if (translated.startsWith("~" + separator()))
        {
            translated = homeDir.getPath() + translated.substring(1);
        }
        else if (translated.startsWith("~"))
        {
            translated = homeDir.getParentFile().getAbsolutePath();
        }
        else if (!(new File(translated).isAbsolute()))
        {
            String cwd = getUserDir().getAbsolutePath();
            translated = cwd + separator() + translated;
        }

        File file = new File(translated);
        final File dir;

        if (translated.endsWith(separator()))
        {
            dir = file;
        }
        else
        {
            dir = file.getParentFile();
        }

        File[] entries = dir == null ? new File[0] : dir.listFiles();
        if(isDirOnly() && entries.length > 0)
        {
            List<File> list = new LinkedList<File>();
            for(File f : entries)
            {
                if(f.isDirectory())
                {
                    list.add(f);
                }
            }
            entries = list.toArray(new File[0]);
        }

        return matchFiles(buffer, translated, entries, candidates);
    }

    protected String separator()
    {
        return File.separator;
    }

    protected File getUserHome()
    {
        return Configuration.getUserHome();
    }

    protected File getUserDir()
    {
        return new File(".");
    }

    protected int matchFiles(final String buffer, final String translated, final File[] files, final List<String> candidates)
    {
        if (files == null)
        {
            return -1;
        }

        int matches = 0;

        // first pass: just count the matches
        for (File file : files)
        {
            if (file.getAbsolutePath().startsWith(translated))
            {
                matches++;
            }
        }
        for (File file : files)
        {
            if (file.getAbsolutePath().startsWith(translated))
            {
                CharSequence name = file.getName() + (matches == 1 && file.isDirectory() ? separator() : " ");
                candidates.add(render(file, name).toString());
            }
        }

        final int index = buffer.lastIndexOf(separator());

        return index + separator().length();
    }

    protected CharSequence render(final File file, final CharSequence name)
    {
        return name;
    }
 }
