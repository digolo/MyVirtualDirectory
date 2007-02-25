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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.controls;


import java.nio.ByteBuffer;

import javax.naming.NamingException;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.Asn1Decoder;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.Asn1Object;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.ControlDecoder;


/**
 * A decoder for SubEntryControls.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SubEntryControlDecoder extends Asn1Decoder implements ControlDecoder
{
    /** The sub entry OID */
    private final static String CONTROL_TYPE_OID = "1.3.6.1.4.1.4203.1.10.1";

    /** The sub entry decoder */
    private static final Asn1Decoder decoder = new Asn1Decoder();

    /**
     * @return the sub entry OID
     */
    public String getControlType()
    {
        return CONTROL_TYPE_OID;
    }

    /**
     * Decode the sub entry control
     * 
     * @param controlBytes The bytes array which contains the encoded sub entry
     * 
     * @return A valid SubEntry object
     * 
     * @throws DecoderException If the decoding found an error
     * @throws NamingException It will never be throw by this method
     */
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException, NamingException
    {
        ByteBuffer bb = ByteBuffer.wrap( controlBytes );
        SubEntryControlContainer container = new SubEntryControlContainer();
        decoder.decode( bb, container );
        return container.getSubEntryControl();
    }
}
