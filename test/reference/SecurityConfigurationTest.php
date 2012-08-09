<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2009 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and
 * accept the LICENSE before you use, modify, and/or redistribute this software.
 *
 * Notes - any changes to the testresources/ESAPI.xml file MUST be reflected in
 * this file or else most (if not all) of these tests will fail.
 *
 * @author  Andrew van der Stock (vanderaj @ owasp.org)
 * @created 2009
 * @since   1.6
 */

require_once dirname(__FILE__) . '/../../src/ESAPI.php';
require_once dirname(__FILE__) . '/../../src/reference/DefaultSecurityConfiguration.php';

class SecurityConfigurationTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        global $ESAPI;

        if (!isset($ESAPI)) {
            $ESAPI = new ESAPI(dirname(__FILE__) . '/../testresources/ESAPI.xml');
        }
    }

    public function tearDown()
    {

    }

    public function testConfigExists()
    {
        $this->assertTrue(file_exists(dirname(__FILE__) . '/../testresources/ESAPI.xml'));
    }
}
