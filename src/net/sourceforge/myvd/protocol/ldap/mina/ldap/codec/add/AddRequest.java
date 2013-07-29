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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.add;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.UniversalTag;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.Value;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapConstants;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.AttributeUtils;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.util.DN;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;


/**
 * An AddRequest Message. Its syntax is : 
 *   AddRequest ::= [APPLICATION 8] SEQUENCE {
 *              entry           LDAPDN,
 *              attributes      AttributeList }
 *
 *   AttributeList ::= SEQUENCE OF SEQUENCE {
 *              type    AttributeDescription,
 *              vals    SET OF AttributeValue }
 * 
 *   AttributeValue ::= OCTET STRING
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddRequest extends LdapMessage
{
    // ~ Static fields/initializers
    // -----------------------------------------------------------------

    /** The logger */
    private static final Logger log = LoggerFactory.getLogger( AddRequest.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    // ~ Instance fields
    // ----------------------------------------------------------------------------

    /** The DN to be added. */
    private LdapDN entry;

   

    /** The add request length */
    private int addRequestLength;

    /** The attributes length */
    private int attributesLength;

    /** The list of all attributes length */
    private List<Integer> attributeLength;

    /** The list of all vals length */
    private List<Integer> valuesLength;
    
    
    
    private LDAPAttributeSet ldapAttribs;
    private DN ldapDN;

    private LDAPAttribute attrib;

    // ~ Constructors
    // -------------------------------------------------------------------------------

    /**
     * Creates a new AddRequest object.
     */
    public AddRequest()
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
        return LdapConstants.ADD_REQUEST;
    }


    /**
     * Initialize the ArrayList for attributes.
     */
    public void initAttributes()
    {
        
        this.ldapAttribs = new LDAPAttributeSet();
    }


    /**
     * Get the entry's attributes to be added
     * 
     * @return Returns the attributes.
     */
    public Attributes getAttributes()
    {
        return null;
    }
    
    public LDAPAttributeSet getAttributeSet() {
    	return this.ldapAttribs;
    }

    /**
     * Create a new attributeValue
     * 
     * @param type The attribute's name (called 'type' in the grammar)
     */
    public void addAttributeType( String type )
    {
        
        
        if (this.attrib == null || ! this.attrib.getName().equalsIgnoreCase(type)) {
        	
        	
        	this.attrib = new LDAPAttribute(type);
        	this.ldapAttribs.add(attrib);
        }
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to be added
     */
    public void addAttributeValue( Object value )
    {
        
        this.attrib.addValue(value.toString());
    }


    /**
     * Get the added DN
     * 
     * @return Returns the entry.
     */
    public LdapDN getEntry()
    {
        return entry;
    }

    public DN getDN() {
    	return this.ldapDN;
    }
    
    
    /**
     * Set the added DN.
     * 
     * @param entry The entry to set.
     */
    public void setEntry( LdapDN entry )
    {
        this.entry = entry;
        
        this.ldapDN = new DN(entry.toString());
    }


    /**
     * Compute the AddRequest length
     * 
     * AddRequest :
     * 
     * 0x68 L1
     *  |
     *  +--> 0x04 L2 entry
     *  +--> 0x30 L3 (attributes)
     *        |
     *        +--> 0x30 L4-1 (attribute)
     *        |     |
     *        |     +--> 0x04 L5-1 type
     *        |     +--> 0x31 L6-1 (values)
     *        |           |
     *        |           +--> 0x04 L7-1-1 value
     *        |           +--> ...
     *        |           +--> 0x04 L7-1-n value
     *        |
     *        +--> 0x30 L4-2 (attribute)
     *        |     |
     *        |     +--> 0x04 L5-2 type
     *        |     +--> 0x31 L6-2 (values)
     *        |           |
     *        |           +--> 0x04 L7-2-1 value
     *        |           +--> ...
     *        |           +--> 0x04 L7-2-n value
     *        |
     *        +--> ...
     *        |
     *        +--> 0x30 L4-m (attribute)
     *              |
     *              +--> 0x04 L5-m type
     *              +--> 0x31 L6-m (values)
     *                    |
     *                    +--> 0x04 L7-m-1 value
     *                    +--> ...
     *                    +--> 0x04 L7-m-n value
     */
    public int computeLength()
    {
        // The entry
        addRequestLength = 1 + TLV.getNbBytes( LdapDN.getNbBytes( entry ) ) + LdapDN.getNbBytes( entry );

        // The attributes sequence
        attributesLength = 0;

        if ( ( this.ldapAttribs != null ) && ( this.ldapAttribs.size() != 0 ) )
        {
            Iterator attributeIterator = this.ldapAttribs.iterator();
            attributeLength = new LinkedList<Integer>();
            valuesLength = new LinkedList<Integer>();

            // Compute the attributes length
            while ( attributeIterator.hasNext() )
            {
                LDAPAttribute attribute = ( LDAPAttribute ) attributeIterator.next();
                int localAttributeLength = 0;
                int localValuesLength = 0;

                // Get the type length
                int idLength = attribute.getName().getBytes().length;
                localAttributeLength = 1 + TLV.getNbBytes( idLength ) + idLength;

                // The values
                
                    Enumeration values = attribute.getByteValues();

                    if ( values.hasMoreElements() )
                    {
                        localValuesLength = 0;

                        while ( values.hasMoreElements() )
                        {
                            Object value = values.nextElement();

                            if ( value instanceof String )
                            {
                                int valueLength = StringTools.getBytesUtf8( ( String ) value ).length;
                                localValuesLength += 1 + TLV.getNbBytes( valueLength ) + valueLength;
                            }
                            else
                            {
                                int valueLength = ( ( byte[] ) value ).length;
                                localValuesLength += 1 + TLV.getNbBytes( valueLength ) + valueLength;
                            }
                        }

                        localAttributeLength += 1 + TLV.getNbBytes( localValuesLength ) + localValuesLength;
                    }

                
                

                // add the attribute length to the attributes length
                attributesLength += 1 + TLV.getNbBytes( localAttributeLength ) + localAttributeLength;

                attributeLength.add(localAttributeLength );
                valuesLength.add( localValuesLength );
            }
        }

        addRequestLength += 1 + TLV.getNbBytes( attributesLength ) + attributesLength;

        // Return the result.
        int result = 1 + TLV.getNbBytes( addRequestLength ) + addRequestLength;

        if ( IS_DEBUG )
        {
            log.debug( "AddRequest PDU length = {}", Integer.valueOf( result ) );
        }

        return result;
    }


    /**
     * Encode the AddRequest message to a PDU. 
     * 
     * AddRequest :
     * 
     * 0x68 LL
     *   0x04 LL entry
     *   0x30 LL attributesList
     *     0x30 LL attributeList
     *       0x04 LL attributeDescription
     *       0x31 LL attributeValues
     *         0x04 LL attributeValue
     *         ... 
     *         0x04 LL attributeValue
     *     ... 
     *     0x30 LL attributeList
     *       0x04 LL attributeDescription
     *       0x31 LL attributeValue
     *         0x04 LL attributeValue
     *         ... 
     *         0x04 LL attributeValue 
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
            // The AddRequest Tag
            buffer.put( LdapConstants.ADD_REQUEST_TAG );
            buffer.put( TLV.getBytes( addRequestLength ) );

            // The entry
            Value.encode( buffer, LdapDN.getBytes( entry ) );

            // The attributes sequence
            buffer.put( UniversalTag.SEQUENCE_TAG );
            buffer.put( TLV.getBytes( attributesLength ) );

            // The partial attribute list
            if ( ( this.ldapAttribs != null ) && ( this.ldapAttribs.size() != 0 ) )
            {
                Iterator attributeIterator = this.ldapAttribs.iterator();
                int attributeNumber = 0;
              
                // Compute the attributes length
                while ( attributeIterator.hasNext() )
                {
                    LDAPAttribute attribute = ( LDAPAttribute ) attributeIterator.next();

                    // The attributes list sequence
                    buffer.put( UniversalTag.SEQUENCE_TAG );
                    int localAttributeLength = attributeLength.get( attributeNumber );
                    buffer.put( TLV.getBytes( localAttributeLength ) );

                    // The attribute type
                    Value.encode( buffer, attribute.getName() );

                    // The values
                    buffer.put( UniversalTag.SET_TAG );
                    int localValuesLength = valuesLength.get( attributeNumber );
                    buffer.put( TLV.getBytes( localValuesLength ) );

                    
                        Enumeration values = attribute.getByteValues();

                        if ( values.hasMoreElements() )
                        {
                            while ( values.hasMoreElements() )
                            {
                                Object value = values.nextElement();

                                if ( value instanceof byte[] )
                                {
                                    Value.encode( buffer, ( byte[] ) value );
                                }
                                else
                                {
                                    Value.encode( buffer, ( String ) value );
                                }
                            }
                        

                    }
                    

                    // Go to the next attribute number;
                    attributeNumber++;
                }
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( "The PDU buffer size is too small !" );
        }

        if ( IS_DEBUG )
        {
            log.debug( "AddRequest encoding : {}", StringTools.dumpBytes( buffer.array() ) );
            log.debug( "AddRequest initial value : {}", toString() );
        }

        return buffer;
    }


    /**
     * Return a String representing an AddRequest
     * 
     * @return A String representing the AddRequest
     */
    public String toString()
    {

        StringBuffer sb = new StringBuffer();

        sb.append( "    Add Request\n" );
        sb.append( "        Entry : '" ).append( entry ).append( "'\n" );
        sb.append( "        Attributes\n" );

        if ( ( this.ldapAttribs == null ) || ( this.ldapAttribs.size() == 0 ) )
        {
            sb.append( "            No attributes\n" );
        }
        else
        {
            sb.append(  "            ").append(this.ldapAttribs.toString() ) ;
        }

        return sb.toString();
    }


    /**
     * @return Returns the currentAttribute type.
     */
    public String getCurrentAttributeType()
    {
        return this.attrib.getName();
    }
}
