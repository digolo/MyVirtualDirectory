/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec;


import java.nio.ByteBuffer;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;


/**
 * A generic LdapResponse Object. It will contain the LdapResult.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapResponse extends LdapMessage
{
    // ~ Instance fields
    // ----------------------------------------------------------------------------

    /** The LdapResult element */
    private LdapResult ldapResult;

    /** The response length */
    private int ldapResponseLength;


    // ~ Constructors
    // -------------------------------------------------------------------------------

    /**
     * Creates a new LdapResponse object.
     */
    public LdapResponse()
    {
        super();
    }


    // ~ Methods
    // ------------------------------------------------------------------------------------

    /**
     * Get the LdapResult
     * 
     * @return Returns the ldapResult.
     */
    public LdapResult getLdapResult()
    {
        return ldapResult;
    }


    /**
     * Set the ldap result
     * 
     * @param ldapResult The ldapResult to set.
     */
    public void setLdapResult( LdapResult ldapResult )
    {
        this.ldapResult = ldapResult;
    }


    /**
     * @return Returns the ldapResponseLength.
     */
    public int getLdapResponseLength()
    {
        return ldapResponseLength;
    }


    /**
     * Compute the LdapResponse length LdapResponse : LdapResult
     */
    public int computeLength()
    {
        ldapResponseLength = ldapResult.computeLength();

        return ldapResponseLength;
    }


    /**
     * Encode the AddResponse message to a PDU.
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     */
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( "Cannot put a PDU in a null buffer !" );
        }

        // The ldapResult
        ldapResult.encode( buffer );

        // The ldapResult
        return buffer;
    }


    /**
     * Get a String representation of an Response
     * 
     * @return An Response String
     */
    public String toString()
    {
        return ( ldapResult != null ? ldapResult.toString() : "" );
    }
}
