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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.List;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapConstants;


/**
 * And Filter Object to store the And filter.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AndFilter extends ConnectorFilter
{
    // ~ Methods
    // ------------------------------------------------------------------------------------

    /**
     * The constructor. We wont initialize the ArrayList as they may not be
     * used.
     */
    public AndFilter( int tlvId )
    {
        super( tlvId );
    }


    /**
     * Get the AndFilter.
     * 
     * @return Returns the andFilter.
     */
    public List<Filter> getAndFilter()
    {
        return filterSet;
    }


    /**
     * Compute the AndFilter length 
     * 
     * AndFilter : 
     * 0xA0 L1 super.computeLength()
     * 
     * Length(AndFilter) = Length(0xA0) + Length(super.computeLength()) +
     *          super.computeLength()
     */
    public int computeLength()
    {
        filtersLength = super.computeLength();

        return 1 + TLV.getNbBytes( filtersLength ) + filtersLength;
    }


    /**
     * Encode the AndFilter message to a PDU. 
     * 
     * AndFilter : 
     * 0xA0 LL
     *  filter.encode() ... filter.encode()
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
            // The AndFilter Tag
            buffer.put( ( byte ) LdapConstants.AND_FILTER_TAG );
            buffer.put( TLV.getBytes( filtersLength ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( "The PDU buffer size is too small !" );
        }

        super.encode( buffer );

        return buffer;
    }


    /**
     * Return a string compliant with RFC 2254 representing an AND filter
     * 
     * @return The AND filter string
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer();

        sb.append( '&' ).append( super.toString() );

        return sb.toString();
    }
}