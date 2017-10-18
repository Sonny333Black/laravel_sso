<?php

/**
 * This file is part of laravel-saml,
 * a SAML IDP integration for laravel. 
 *
 * @license MIT
 * @package kingstarter/laravel-saml
 */

return [

    /*
    |--------------------------------------------------------------------------
    | Base settings
    |--------------------------------------------------------------------------
    |
    | General package settings
    |
    */

    // Include the pre-defined routes from package or not.
    'use_package_routes' => true,
    
    // Forward user roles
    // This option requires entrust to be installed and
    // the user model to support the roles() method. Otherwise an empty
    // array of user roles will be forwarded.
    'forward_roles' => false,
    
    // Allow debugging within SamlAuth trait to get SP data during SAML auth
    // request. The debug output is written to storage/logs/laravel.log.
    'debug_saml_request' => false,

    /*
    |--------------------------------------------------------------------------
    | IDP (identification provider) settings
    |--------------------------------------------------------------------------
    |
    | Set overall configuration for laravel as idp server.
    |
    | All files are in storage/saml and referenced via Storage::disk('saml') 
    | as root directory. To have a valid storage configuration, add the root  
    | path to the config/filesystem.php file.
    |
    */
    
    'idp' => [
        'metadata'  => 'idp/metadata.xml',
        'cert'      => 'idp/cert.pem',
        'key'       => 'idp/key.pem',
    ],

    /*
    |--------------------------------------------------------------------------
    | SP (service provider) settings
    |--------------------------------------------------------------------------
    |
    | Array of service provider data. Add your list of SPs here.
    |
    | An SP is defined by its consumer service URL which is base64 encoded. 
    | It contains the destination, issuer, cert and cert-key. 
    |
    */

    'sp' => [

        /**
         * New entry
         *
         * Sample URL:         drive.google.com/a/digitalvillage.de
         * Base64 encoded URL: ZHJpdmUuZ29vZ2xlLmNvbS9hL2RpZ2l0YWx2aWxsYWdlLmRl==
         */
        'aHR0cHM6Ly9zcC53ZWJhcHAuY29tL3NhbWwvY29uc3VtZQ==' => [
            'destination' => 'https://drive.google.com/a/digitalvillage.de/saml/consume',
            'issuer'      => 'https://drive.google.com',
        ],
        
    ],
    
];
