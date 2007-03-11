/*
 * This class was automatically generated with 
 * <a href="http://www.castor.org">Castor 1.1</a>, using an XML
 * Schema.
 * $Id$
 */

package net.sourceforge.myvd.higgins.idas.contextProvider.config;

  //---------------------------------/
 //- Imported classes and packages -/
//---------------------------------/

import org.exolab.castor.xml.Marshaller;
import org.exolab.castor.xml.Unmarshaller;

/**
 * Class MyVDHigginsConfig.
 * 
 * @version $Revision$ $Date$
 */
public class MyVDHigginsConfig implements java.io.Serializable {


      //--------------------------/
     //- Class/Member Variables -/
    //--------------------------/

    /**
     * Field _configFile.
     */
    private java.lang.String _configFile;

    /**
     * Field _userSearchBase.
     */
    private java.lang.String _userSearchBase;

    /**
     * Field _userIdAttribute.
     */
    private java.lang.String _userIdAttribute;


      //----------------/
     //- Constructors -/
    //----------------/

    public MyVDHigginsConfig() {
        super();
    }


      //-----------/
     //- Methods -/
    //-----------/

    /**
     * Returns the value of field 'configFile'.
     * 
     * @return the value of field 'ConfigFile'.
     */
    public java.lang.String getConfigFile(
    ) {
        return this._configFile;
    }

    /**
     * Returns the value of field 'userIdAttribute'.
     * 
     * @return the value of field 'UserIdAttribute'.
     */
    public java.lang.String getUserIdAttribute(
    ) {
        return this._userIdAttribute;
    }

    /**
     * Returns the value of field 'userSearchBase'.
     * 
     * @return the value of field 'UserSearchBase'.
     */
    public java.lang.String getUserSearchBase(
    ) {
        return this._userSearchBase;
    }

    /**
     * Method isValid.
     * 
     * @return true if this object is valid according to the schema
     */
    public boolean isValid(
    ) {
        try {
            validate();
        } catch (org.exolab.castor.xml.ValidationException vex) {
            return false;
        }
        return true;
    }

    /**
     * 
     * 
     * @param out
     * @throws org.exolab.castor.xml.MarshalException if object is
     * null or if any SAXException is thrown during marshaling
     * @throws org.exolab.castor.xml.ValidationException if this
     * object is an invalid instance according to the schema
     */
    public void marshal(
            final java.io.Writer out)
    throws org.exolab.castor.xml.MarshalException, org.exolab.castor.xml.ValidationException {
        Marshaller.marshal(this, out);
    }

    /**
     * 
     * 
     * @param handler
     * @throws java.io.IOException if an IOException occurs during
     * marshaling
     * @throws org.exolab.castor.xml.ValidationException if this
     * object is an invalid instance according to the schema
     * @throws org.exolab.castor.xml.MarshalException if object is
     * null or if any SAXException is thrown during marshaling
     */
    public void marshal(
            final org.xml.sax.ContentHandler handler)
    throws java.io.IOException, org.exolab.castor.xml.MarshalException, org.exolab.castor.xml.ValidationException {
        Marshaller.marshal(this, handler);
    }

    /**
     * Sets the value of field 'configFile'.
     * 
     * @param configFile the value of field 'configFile'.
     */
    public void setConfigFile(
            final java.lang.String configFile) {
        this._configFile = configFile;
    }

    /**
     * Sets the value of field 'userIdAttribute'.
     * 
     * @param userIdAttribute the value of field 'userIdAttribute'.
     */
    public void setUserIdAttribute(
            final java.lang.String userIdAttribute) {
        this._userIdAttribute = userIdAttribute;
    }

    /**
     * Sets the value of field 'userSearchBase'.
     * 
     * @param userSearchBase the value of field 'userSearchBase'.
     */
    public void setUserSearchBase(
            final java.lang.String userSearchBase) {
        this._userSearchBase = userSearchBase;
    }

    /**
     * Method unmarshal.
     * 
     * @param reader
     * @throws org.exolab.castor.xml.MarshalException if object is
     * null or if any SAXException is thrown during marshaling
     * @throws org.exolab.castor.xml.ValidationException if this
     * object is an invalid instance according to the schema
     * @return the unmarshaled
     * net.sourceforge.myvd.higgins.idas.contextProvider.config.MyVDHigginsConfig
     */
    public static net.sourceforge.myvd.higgins.idas.contextProvider.config.MyVDHigginsConfig unmarshal(
            final java.io.Reader reader)
    throws org.exolab.castor.xml.MarshalException, org.exolab.castor.xml.ValidationException {
        return (net.sourceforge.myvd.higgins.idas.contextProvider.config.MyVDHigginsConfig) Unmarshaller.unmarshal(net.sourceforge.myvd.higgins.idas.contextProvider.config.MyVDHigginsConfig.class, reader);
    }

    /**
     * 
     * 
     * @throws org.exolab.castor.xml.ValidationException if this
     * object is an invalid instance according to the schema
     */
    public void validate(
    )
    throws org.exolab.castor.xml.ValidationException {
        org.exolab.castor.xml.Validator validator = new org.exolab.castor.xml.Validator();
        validator.validate(this);
    }

}
