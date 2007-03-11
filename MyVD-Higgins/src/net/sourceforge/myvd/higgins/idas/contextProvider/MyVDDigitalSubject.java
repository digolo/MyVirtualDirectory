/**
 * Copyright (c) 2006 Novell, Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; version 2.1 of the license.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, contact Novell, Inc.
 *
 * To contact Novell about this file by physical or electronic mail,
 * you may find current contact information at www.novell.com
 * 
 * Changes Copyright (c) 2007 Marc Boorshtein
 * 
 */

package net.sourceforge.myvd.higgins.idas.contextProvider;

import java.net.URI;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

import net.sourceforge.myvd.types.Entry;

import org.eclipse.higgins.idas.IAttribute;
import org.eclipse.higgins.idas.IContext;
import org.eclipse.higgins.idas.IDigitalSubject;
import org.eclipse.higgins.idas.IMetadata;
import org.eclipse.higgins.idas.IPropertyValue;
import org.eclipse.higgins.idas.IdASException;
import org.eclipse.higgins.idas.NotImplementedException;
import org.eclipse.higgins.idas.impl.BasicAttribute;
import org.eclipse.higgins.idas.impl.BasicMetadata;
import org.eclipse.higgins.idas.impl.BasicSimpleValue;
import org.eclipse.higgins.idas.impl.BasicValueBase64Binary;
import org.eclipse.higgins.idas.impl.BasicValueString;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPException;

/**
*
* @author jimse@novell.com
* @author tdoman@novell.com
*
*/

public class MyVDDigitalSubject implements IDigitalSubject
{
	private MyVDContext _context;
	private HashSet<IMetadata> _metaData;
	private Entry entry;

	
	
	public MyVDDigitalSubject(
			MyVDContext jndiContext,
			Entry entry
			) throws IdASException
		{
			_context = jndiContext;
			this.entry = entry;
		}

	/**
	 */
	public IContext getContext() throws IdASException
	{
		return _context;
	}

	/**
	 */
	public String getUniqueID() throws IdASException
	{
		return _context.mapNameOut(entry.getEntry().getDN());
	}

	/**
	 */
	public URI getType() throws IdASException
	{
		return _context.getType(this.entry);
	}

	/**
	 */
	public IAttribute createAttribute(
		URI arg0,
		Object arg1) throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public void addAttribute(
		IAttribute arg0) throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public void removeAttribute(
		IAttribute arg0) throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public Iterable<IAttribute> getAttributes() throws IdASException
	{
		//Attributes jndiAttrs = _jndiResult.getAttributes();
		//NamingEnumeration<? extends Attribute> jndiEnum;
		HashSet<IAttribute> attrs = new HashSet<IAttribute>();

		//jndiEnum = jndiAttrs.getAll();
		LDAPAttributeSet attribs = entry.getEntry().getAttributeSet();
		Iterator it = attribs.iterator();
		while (it.hasNext())
		{
			LDAPAttribute jndiAttr = (LDAPAttribute) it.next();

			Enumeration jndiAttrValEnum = jndiAttr.getByteValues();
			// Set OWL type.
			BasicAttribute attr = new BasicAttribute(_context.mapAttrToURI(jndiAttr.getName()));					
			while (jndiAttrValEnum.hasMoreElements())
			{
				byte[] jndiValue = (byte[]) jndiAttrValEnum.nextElement();
				IPropertyValue value = null;

				
					System.out.println("Attr: " + jndiAttr.getName() + "is a byte[]");
					value = new BasicValueBase64Binary((byte [])jndiValue);
				

				attr.setValue(value);
			}
			attrs.add(attr);
		}

		return attrs; 
	}
	

	/**
	 */
	public IAttribute getAttribute(
		URI attrName) throws IdASException
	{
		LDAPAttributeSet attribs = this.entry.getEntry().getAttributeSet();
		BasicAttribute attr = null;

		Iterator it = attribs.iterator();
		while (it.hasNext())
		{
			LDAPAttribute jndiAttr = (LDAPAttribute) it.next();

			// Set OWL type.
			URI mappedAttr = _context.mapAttrToURI(jndiAttr.getName());
			if (attrName.compareTo(mappedAttr) == 0)
			{
				Enumeration jndiAttrValEnum = jndiAttr.getByteValues();
				attr = new BasicAttribute(mappedAttr);					
				while (jndiAttrValEnum.hasMoreElements())
				{
					byte[]  jndiValue = (byte[]) jndiAttrValEnum.nextElement();
					IPropertyValue value = null;

					
					System.out.println("Attr: " + jndiAttr.getName() + "is a byte[]");
					value = new BasicValueBase64Binary((byte [])jndiValue);
					
					attr.setValue(value);
				}
				break;
			}
		}

		return attr;
	}

	/**
	 */
	public IMetadata createMetadata(
		URI type,
		IPropertyValue value) throws IdASException
	{
		return new BasicMetadata(type, value);
	}

	/**
	 */
	public void addMetadata(
		IMetadata metadata) throws IdASException
	{
		_getMetadataSet().add(metadata);
	}

	/**
	 */
	public void	removeMetadata(
		IMetadata metadata) throws IdASException
	{
		_getMetadataSet().remove(metadata);
	}

	/**
	 */
	public Iterable<IMetadata> getMetadataSet() throws IdASException
	{
		return _getMetadataSet();
	}

	/**
	 */
	private HashSet<IMetadata> _getMetadataSet() throws IdASException
	{
		if (_metaData == null)
			_metaData = new HashSet<IMetadata>();
		return _metaData;
	}

	public IAttribute createAttribute(
		URI arg0,
		IPropertyValue arg1) throws IdASException
	{
		throw new NotImplementedException();
	}

	public IAttribute createAttribute(
		URI arg0,
		Iterable<IPropertyValue> arg1) throws IdASException
	{
		throw new NotImplementedException();
	}
}
