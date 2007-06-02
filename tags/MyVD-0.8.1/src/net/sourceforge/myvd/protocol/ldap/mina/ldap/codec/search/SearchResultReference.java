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


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.Value;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapConstants;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.util.LdapURL;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


/**
 * A SearchResultReference Message. Its syntax is : 
 * 
 * SearchResultReference ::= [APPLICATION 19] SEQUENCE OF LDAPURL
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchResultReference extends LdapMessage
{
    // ~ Instance fields
    // ----------------------------------------------------------------------------

    /** The set of LdapURLs */
    private List<LdapURL> searchResultReferences = new ArrayList<LdapURL>();

    /** The search result reference length */
    private int searchResultReferenceLength;


    // ~ Constructors
    // -------------------------------------------------------------------------------

    /**
     * Creates a new SearchResultEntry object.
     */
    public SearchResultReference()
    {
        super();
    }


    // ~ Methods
    // ------------------------------------------------------------------------------------

    /**
     * Get the message type
     * 
     * @return Returns the type.
     */
    public int getMessageType()
    {
        return LdapConstants.SEARCH_RESULT_REFERENCE;
    }


    /**
     * Add a new reference to the list.
     * 
     * @param searchResultReference The search result reference
     */
    public void addSearchResultReference( LdapURL searchResultReference )
    {
        searchResultReferences.add( searchResultReference );
    }


    /**
     * Get the list of references
     * 
     * @return An ArrayList of SearchResultReferences
     */
    public List<LdapURL> getSearchResultReferences()
    {
        return searchResultReferences;
    }


    /**
     * Compute the SearchResultReference length
     * 
     * SearchResultReference :
     * 
     * 0x73 L1
     *  |
     *  +--> 0x04 L2 reference
     *  +--> 0x04 L3 reference
     *  +--> ...
     *  +--> 0x04 Li reference
     *  +--> ...
     *  +--> 0x04 Ln reference
     * 
     * L1 = n*Length(0x04) + sum(Length(Li)) + sum(Length(reference[i]))
     * 
     * Length(SearchResultReference) = Length(0x73 + Length(L1) + L1
     */
    public int computeLength()
    {
        searchResultReferenceLength = 0;

        Iterator referencesIterator = searchResultReferences.iterator();

        // We may have more than one reference.
        while ( referencesIterator.hasNext() )
        {
            int ldapUrlLength = ( ( LdapURL ) referencesIterator.next() ).getNbBytes();
            searchResultReferenceLength += 1 + TLV.getNbBytes( ldapUrlLength ) + ldapUrlLength;
        }

        return 1 + TLV.getNbBytes( searchResultReferenceLength ) + searchResultReferenceLength;
    }


    /**
     * Encode the SearchResultReference message to a PDU.
     * 
     * SearchResultReference :
     * 
     * 0x73 LL
     *   0x04 LL reference
     *   [0x04 LL reference]*
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
            // The SearchResultReference Tag
            buffer.put( LdapConstants.SEARCH_RESULT_REFERENCE_TAG );
            buffer.put( TLV.getBytes( searchResultReferenceLength ) );

            // The references. We must at least have one reference
            Iterator referencesIterator = searchResultReferences.iterator();

            // We may have more than one reference.
            while ( referencesIterator.hasNext() )
            {
                LdapURL reference = ( ( LdapURL ) referencesIterator.next() );

                // Encode the reference
                Value.encode( buffer, reference.getString() );
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( "The PDU buffer size is too small !" );
        }

        return buffer;
    }


    /**
     * Returns the Search Result Reference string
     * 
     * @return The Search Result Reference string
     */
    public String toString()
    {

        StringBuffer sb = new StringBuffer();

        sb.append( "    Search Result Reference\n" );

        if ( ( searchResultReferences == null ) || ( searchResultReferences.size() == 0 ) )
        {
            sb.append( "        No Reference\n" );
        }
        else
        {
            sb.append( "        References\n" );

            for ( LdapURL url:searchResultReferences )
            {
                sb.append( "            '" ).append( url ).append(
                    "'\n" );
            }
        }

        return sb.toString();
    }
}
