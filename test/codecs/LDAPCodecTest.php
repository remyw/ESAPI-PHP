<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author  Andrew van der Stock < van der aj ( at ) owasp. org >
 * @created 2009
 */

require_once dirname(__FILE__) . '/../../src/ESAPI.php';
// require_once dirname(__FILE__).'/../../src/codecs/LDAPCodec.php';


class LDAPCodecTest extends PHPUnit_Framework_TestCase
{
    private $ldapCodec = null;

    public function setUp()
    {
        global $ESAPI;

        if (!isset($ESAPI)) {
            $ESAPI = new ESAPI();
        }

        // $this->ldapCodec = new LDAPCodec();
    }

    public function testEncode()
    {
        $this->markTestIncomplete('This test has not been implemented yet.');
        $immune = array("");

        $this->fail();

        $this->assertEquals('TODO', $this->ldapCodec->encode($immune, "esapi)(|(password=*)"));
    }

    public function testEncodeCharacter()
    {
        $this->markTestIncomplete('This test has not been implemented yet.');
        $immune = array("");
        $this->fail();
        $this->assertEquals("TODO", $this->ldapCodec->encode($immune, "<"));
    }

    public function testDecode()
    {
        $this->markTestIncomplete('This test has not been implemented yet.');
        $this->fail();
        $this->assertEquals("esapi)(|(password=*)", $this->ldapCodec->decode('TODO'));
    }

    public function testDecodeCharacter()
    {
        $this->markTestIncomplete('This test has not been implemented yet.');
        $this->fail();
        $this->assertEquals("<", $this->ldapCodec->decode("TODO"));
    }

}