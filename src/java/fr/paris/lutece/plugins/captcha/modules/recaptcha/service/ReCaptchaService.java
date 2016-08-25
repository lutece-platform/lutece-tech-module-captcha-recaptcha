/*
 * Copyright (c) 2002-2016, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.captcha.modules.recaptcha.service;

import fr.paris.lutece.portal.service.datastore.DatastoreService;
import fr.paris.lutece.portal.service.plugin.PluginService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.util.httpaccess.HttpAccess;

import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.io.StringReader;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import javax.servlet.http.HttpServletRequest;


public class ReCaptchaService implements IReCaptchaService
{
    private static boolean _bActive;
    private static final String PARAM_SECRET = "secret";
    private static final String PARAM_RESPONSE = "response";
    private static final String PARAM_SUCCESS = "success";
    private static final String PARAM_REMOTEIP = "remoteip";
    private static final String PARAM_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    private static final String DSKEY_SITE_KEY = "recaptcha.site_property.siteKey";
    private static final String DSKEY_SECRET_KEY = "recaptcha.site_property.sercretKey";
    private static final String DSKEY_URL_VERIFY = "recaptcha.site_property.urlVerify";

    /**
     * Default constructor.
     *
     * Gets the ReCaptchaValidator from the ReCaptcha module.
     * If the validator is missing, sets available to false;
     */
    public ReCaptchaService(  )
    {
        _bActive = PluginService.isPluginEnable( "recaptcha" );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getHtmlCode(  )
    {
        String strKeySite = DatastoreService.getDataValue( DSKEY_SITE_KEY, "" );

        if ( isActive(  ) && StringUtils.isNotBlank( strKeySite ) )
        {
            return "<div class=\"g-recaptcha\" data-sitekey=\"" + strKeySite + "\"></div>";
        }
        else
        {
            return StringUtils.EMPTY;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean validate( HttpServletRequest request )
    {
        String gRecaptchaResponse = request.getParameter( PARAM_RECAPTCHA_RESPONSE );
        AppLogService.info( gRecaptchaResponse );

        boolean verify = false;

        try
        {
            verify = verify( gRecaptchaResponse, request );
        }
        catch ( IOException e )
        {
            AppLogService.error( e.getMessage(  ) );
        }

        if ( isActive(  ) && verify )
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    private boolean verify( String gRecaptchaResponse, HttpServletRequest request )
        throws IOException
    {
        String strSecretKey = DatastoreService.getDataValue( DSKEY_SECRET_KEY, "" );
        String strUrl = DatastoreService.getDataValue( DSKEY_URL_VERIFY,
                "https://www.google.com/recaptcha/api/siteverify" );

        if ( ( gRecaptchaResponse == null ) || "".equals( gRecaptchaResponse ) || "".equals( strSecretKey ) ||
                "".equals( strUrl ) )
        {
            AppLogService.error( "Vérifier les paramètres du sites (clé du site, clé secrete, url recaptcha" );

            return false;
        }

        try
        {
            HttpAccess httpAccess = new HttpAccess(  );
            Map<String, String> mapParameters = new ConcurrentHashMap<String, String>(  );

            mapParameters.put( PARAM_SECRET, strSecretKey );
            mapParameters.put( PARAM_RESPONSE, gRecaptchaResponse );
            mapParameters.put( PARAM_REMOTEIP, request.getRemoteAddr(  ) );

            String strJson = httpAccess.doPost( strUrl, mapParameters );

            JsonReader jsonReader = Json.createReader( new StringReader( strJson ) );
            JsonObject jsonObject = jsonReader.readObject(  );
            jsonReader.close(  );

            return jsonObject.getBoolean( PARAM_SUCCESS );
        }
        catch ( Exception e )
        {
            AppLogService.error( e.getMessage(  ) );

            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isActive(  )
    {
        return _bActive;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setActive( boolean isActive )
    {
        _bActive = isActive;
    }
}
