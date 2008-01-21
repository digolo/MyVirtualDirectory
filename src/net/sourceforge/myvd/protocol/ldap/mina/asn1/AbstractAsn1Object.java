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
package net.sourceforge.myvd.protocol.ldap.mina.asn1;


import java.nio.ByteBuffer;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;


/**
 * An abstract class which implements basic TLV operations.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractAsn1Object implements Asn1Object
{
    // ~ Instance fields
    // ----------------------------------------------------------------------------

    /** The object's current length. It is used while decoding PDUs */
    private int currentLength;

    /** The object's expected length. It is used while decoding PDUs */
    private int expectedLength;

    /** The encapsulating Object */
    protected AbstractAsn1Object parent;

    
    /** The identifier of the asqsocaited TLV */
    private transient int tlvId;

    // ~ Methods
    // ------------------------------------------------------------------------------------

    /**
     * Constructor associated with a TLV indentifier. Used when 
     * decoded a TLV, we create an association between the decode
     * Asn1Object and the TLV which is the encoded form.
     * 
     * @param tlvId The TLV Id.
     */
    protected AbstractAsn1Object( int tlvId )
    {
        this.tlvId = tlvId;
    }

    
    /**
     * Default constructor. The TLV Id is set to -1. This constructor
     * is called when an Asn1Object is created to be encoded, not decoded.
     */
    protected AbstractAsn1Object()
    {
        this.tlvId = -1;
    }
    
    /**
     * Get the current object length, which is the sum of all inner length
     * already decoded.
     * 
     * @return The current object's length
     */
    public int getCurrentLength()
    {
        return currentLength;
    }


    /**
     * Compute the object length, which is the sum of all inner length.
     * 
     * @return The object's computed length
     */
    public abstract int computeLength();


    /**
     * Encode the object to a PDU.
     * 
     * @param buffer
     *            The buffer where to put the PDU
     * @return The PDU.
     */
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        return null;
    }


    /**
     * Get the expected object length.
     * 
     * @return The expected object's length
     */
    public int getExpectedLength()
    {
        return expectedLength;
    }


    /**
     * Add a length to the object
     * 
     * @param length
     *            The length to add.
     * @throws DecoderException
     *             Thrown if the current length exceed the expected length
     */
    public void addLength( int length ) throws DecoderException
    {
        currentLength += length;

        if ( currentLength > expectedLength )
        {
            throw new DecoderException( "Current Length is above expected Length" );
        }
    }


    /**
     * Set the expected length
     * 
     * @param expectedLength
     *            The expectedLength to set.
     */
    public void setExpectedLength( int expectedLength )
    {
        this.expectedLength = expectedLength;
    }


    /**
     * Set the current length
     * 
     * @param currentLength
     *            The currentLength to set.
     */
    public void setCurrentLength( int currentLength )
    {
        this.currentLength = currentLength;
    }


    /**
     * Get the parent
     * 
     * @return Returns the parent.
     */
    public AbstractAsn1Object getParent()
    {
        return parent;
    }


    /**
     * Set the parent
     * 
     * @param parent
     *            The parent to set.
     */
    public void setParent( AbstractAsn1Object parent )
    {
        this.parent = parent;
    }

    /**
     * @return The TLV identifier associated with this object
     */
    public int getTlvId()
    {
        return tlvId;
    }
}
