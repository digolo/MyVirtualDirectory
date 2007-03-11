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
 */

package net.sourceforge.myvd.higgins.idas.contextProvider;

import java.security.Provider;

public final class MyVDContextFactoryProvider extends Provider
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public MyVDContextFactoryProvider()
	{
		super("NovellJNDIHigginsProvider", 1.0, "Novell JDNI provider for Higgins ContextFactory objects.");
		put("ContextFactory.Novell.JNDI", "org.bandit.higgins.cp.jndi.JNDIContextFactory");
	}
}
