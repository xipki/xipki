/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
