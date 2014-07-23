/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.console.karaf;

import java.io.File;
import java.io.FileFilter;
import java.util.List;

import org.apache.karaf.shell.console.completer.StringsCompleter;

/**
 * @author Lijun Liao
 */

public abstract class PathCompleter
{

    private static class PrefixFileFilter implements FileFilter
    {
        private boolean dirOnly;
        private String prefix;
        public PrefixFileFilter(String prefix, boolean dirOnly)
        {
            this.prefix = prefix;
            this.dirOnly = dirOnly;
        }

        @Override
        public boolean accept(File pathname)
        {
            if(dirOnly && pathname.isDirectory() == false)
            {
                return false;
            }

            return pathname.getName().startsWith(prefix);
        }
    }

    protected abstract boolean isDirOnly();

    public int complete(String buffer, int cursor, List<String> candidates)
    {
        StringsCompleter delegate = new StringsCompleter();

        if(buffer == null || buffer.isEmpty())
        {
            return delegate.complete(buffer, cursor, candidates);
        }

        String path = null;
        File[] children = null;

        File f = new File(buffer);
        if(f.exists())
        {
            if(f.isDirectory())
            {
                path = f.getPath();
                children = f.listFiles();
            }
        }
        else
        {
            File p = f.getParentFile();
            if(p == null)
            {
                p = new File(".");
                path = "";
            }
            else
            {
                path = p.getPath();
            }

            children = p.listFiles(new PrefixFileFilter(f.getName(), isDirOnly()));
        }

        if(path != null)
        {
            if(path.isEmpty() == false && path.endsWith(File.separator) == false)
            {
                path += File.separator;
            }

            if(children != null)
            {
                for(File child : children)
                {
                    if(child.isDirectory())
                    {
                        String childName = child.getName();
                        delegate.getStrings().add(path + childName);
                        delegate.getStrings().add(path + childName + File.separator);
                    }
                    else if(isDirOnly() == false)
                    {
                        String childName = child.getName();
                        delegate.getStrings().add(path + childName);
                    }
                }
            }
        }

        return delegate.complete(buffer, cursor, candidates);
    }

}
