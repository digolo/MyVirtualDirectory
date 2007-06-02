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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.modifyDn;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapConstants;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapResponse;


/**
 * An ModifyDNResponse Message. Its syntax is : 
 * 
 * ModifyDNResponse ::= [APPLICATION 13] LDAPResult
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ModifyDNResponse extends LdapResponse
{
    // ~ Constructors
    // -------------------------------------------------------------------------------

    /**
     * Creates a new ModifyDNResponse object.
     */
    public ModifyDNResponse()
    {
        super();
    }


    /**
     * Get the message type
     * 
     * @return Returns the type.
     */
    public int getMessageType()
    {
        return LdapConstants.MODIFYDN_RESPONSE;
    }


    /**
     * Compute the ModifyDNResponse length 
     * 
     * ModifyDNResponse : 
     * 0x6D L1 
     *   | 
     *   +--> LdapResult 
     *   
     * L1 = Length(LdapResult) 
     * Length(ModifyDNResponse) = Length(0x6D) + Length(L1) + L1
     */
    public int computeLength()
    {
        int ldapResponseLength = super.computeLength();

        return 1 + TLV.getNbBytes( ldapResponseLength ) + ldapResponseLength;
    }


    /**
     * Encode the ModifyDNResponse message to a PDU.
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

        try
        {
            // The tag
            buffer.put( LdapConstants.MODIFY_DN_RESPONSE_TAG );
            buffer.put( TLV.getBytes( getLdapResponseLength() ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( "The PDU buffer size is too small !" );
        }

        // The ldapResult
        return super.encode( buffer );
    }


    /**
     * Get a String representation of a ModifyDNResponse
     * 
     * @return A ModifyDNResponse String
     */
    public String toString()
    {

        StringBuffer sb = new StringBuffer();

        sb.append( "    Modify DN Response\n" );
        sb.append( super.toString() );

        return sb.toString();
    }
}
