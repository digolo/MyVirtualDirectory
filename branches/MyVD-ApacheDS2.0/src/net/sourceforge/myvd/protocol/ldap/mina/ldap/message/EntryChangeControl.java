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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.message;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.controls.ChangeType;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A response control that may be returned by Persistent Search entry responses.
 * It contains addition change information to descrive the exact change that
 * occured to an entry. The exact details of this control are covered in section
 * 5 of this (yes) expired draft: <a
 * href="http://www3.ietf.org/proceedings/01aug/I-D/draft-ietf-ldapext-psearch-03.txt">
 * Persistent Search Draft v03</a> which is printed out below for convenience:
 * 
 * <pre>
 *    5.  Entry Change Notification Control
 *    
 *    This control provides additional information about the change the caused
 *    a particular entry to be returned as the result of a persistent search.
 *    The controlType is &quot;2.16.840.1.113730.3.4.7&quot;.  If the client set the
 *    returnECs boolean to TRUE in the PersistentSearch control, servers MUST
 *    include an EntryChangeNotification control in the Controls portion of
 *    each SearchResultEntry that is returned due to an entry being added,
 *    deleted, or modified.
 *    
 *               EntryChangeNotification ::= SEQUENCE 
 *               {
 *                         changeType ENUMERATED 
 *                         {
 *                                 add             (1),
 *                                 delete          (2),
 *                                 modify          (4),
 *                                 modDN           (8)
 *                         },
 *                         previousDN   LDAPDN OPTIONAL,     -- modifyDN ops. only
 *                         changeNumber INTEGER OPTIONAL     -- if supported
 *               }
 *    
 *    changeType indicates what LDAP operation caused the entry to be returned.
 *    
 *    previousDN is present only for modifyDN operations and gives the DN of
 *    the entry before it was renamed and/or moved.  Servers MUST include this
 *    optional field only when returning change notifications as a result of
 *    modifyDN operations.
 * 
 *    changeNumber is the change number [CHANGELOG] assigned by a server for
 *    the change.  If a server supports an LDAP Change Log it SHOULD include
 *    this field.
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 437007 $
 */
public class EntryChangeControl extends ControlImpl
{
    private static final long serialVersionUID = -2356861450876343999L;

    private static final Logger log = LoggerFactory.getLogger( EntryChangeControl.class );

    public static final String CONTROL_OID = "2.16.840.1.113730.3.4.7";

    public static final int UNDEFINED_CHANGE_NUMBER = net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.controls.EntryChangeControl.UNDEFINED_CHANGE_NUMBER;

    private ChangeType changeType = ChangeType.ADD;

    private int changeNumber = UNDEFINED_CHANGE_NUMBER;

    private LdapDN previousDn = null;


    public EntryChangeControl()
    {
        super();
        setType( CONTROL_OID );
    }


    public ChangeType getChangeType()
    {
        return changeType;
    }


    public void setChangeType( ChangeType changeType )
    {
        this.changeType = changeType;
    }


    public LdapDN getPreviousDn()
    {
        return previousDn;
    }


    public void setPreviousDn( LdapDN previousDn )
    {
        this.previousDn = previousDn;
    }


    public int getChangeNumber()
    {
        return changeNumber;
    }


    public void setChangeNumber( int changeNumber )
    {
        this.changeNumber = changeNumber;
    }


    public byte[] getEncodedValue()
    {
        if ( getValue() == null )
        {
            // should call this codec or something
            net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.controls.EntryChangeControl ecc = new net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.controls.EntryChangeControl();
            ecc.setChangeNumber( changeNumber );
            ecc.setChangeType( changeType );
            ecc.setPreviousDn( previousDn );

            try
            {
                setValue( ecc.encode( null ).array() );
            }
            catch ( EncoderException e )
            {
                log.error( "Failed to encode psearch control", e );
            }
        }

        return getValue();
    }
}
