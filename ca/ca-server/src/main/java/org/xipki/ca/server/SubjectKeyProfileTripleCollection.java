/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server;

import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class SubjectKeyProfileTripleCollection
{
    private final List<SubjectKeyProfileTriple> triples = new LinkedList<>();

    public SubjectKeyProfileTripleCollection()
    {
    }

    public void addTriple(SubjectKeyProfileTriple triple)
    {
        if(triple != null)
        {
            triples.add(triple);
        }
    }

    public SubjectKeyProfileTriple getFirstTriple(String sha1FpSubject, String sha1FpKey, String profileName)
    {
        for(SubjectKeyProfileTriple triple : triples)
        {
            if(sha1FpSubject.equals(triple.getSubjectFp()) &&
                    sha1FpKey.equals(triple.getKeyFp()) &&
                    profileName.equals(triple.getProfile()))
            {
                return triple;
            }
        }

        return null;
    }

    public boolean hasTripleForSubjectAndKey(String sha1FpSubject, String sha1FpKey)
    {
        for(SubjectKeyProfileTriple triple : triples)
        {
            if(sha1FpSubject.equals(triple.getSubjectFp()) &&
                    sha1FpKey.equals(triple.getKeyFp()))
            {
                return true;
            }
        }

        return false;
    }

    public boolean hasTripleForSubject(String sha1FpSubject)
    {
        for(SubjectKeyProfileTriple triple : triples)
        {
            if(sha1FpSubject.equals(triple.getSubjectFp()))
            {
                return true;
            }
        }

        return false;
    }

    public boolean hasTripleForKey(String sha1FpKey)
    {
        for(SubjectKeyProfileTriple triple : triples)
        {
            if(sha1FpKey.equals(triple.getKeyFp()))
            {
                return true;
            }
        }

        return false;
    }

    public boolean hasTripleForSubjectAndProfile(String sha1FpSubject, String profileName)
    {
        for(SubjectKeyProfileTriple triple : triples)
        {
            if(sha1FpSubject.equals(triple.getSubjectFp()) &&
                    profileName.equals(triple.getProfile()))
            {
                return true;
            }
        }

        return false;
    }

    public boolean hasTripleForKeyAndProfile(String sha1FpKey, String profileName)
    {
        for(SubjectKeyProfileTriple triple : triples)
        {
            if(sha1FpKey.equals(triple.getKeyFp()) &&
                    profileName.equals(triple.getProfile()))
            {
                return true;
            }
        }

        return false;
    }

    public boolean isEmpty()
    {
        return triples.isEmpty();
    }

}
