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
require_once dirname(__FILE__) . '/../../src/codecs/WindowsCodec.php';


class WindowsCodecTest extends PHPUnit_Framework_TestCase
{
    private $windowsCodec = null;

    public function setUp()
    {
        global $ESAPI;

        if (!isset($ESAPI)) {
            $ESAPI = new ESAPI();
        }

        $this->windowsCodec = new WindowsCodec();
    }

    public function tearDown()
    {

    }

    public function testEncode()
    {
        $immune = array("");

        $this->assertEquals('^"^ ^&^ dir^/s^ c^:', $this->windowsCodec->encode($immune, '" & dir/s c:'));
    }

    public function testEncodeCharacter()
    {
        $immune = array("");

        $this->assertEquals("^<", $this->windowsCodec->encode($immune, "<"));
    }

    public function testDecode()
    {
        $this->assertEquals('" & dir/s c:', $this->windowsCodec->decode('^"^ ^&^ dir^/s^ c^:'));
    }

    public function testDecodeCharacter()
    {
        $this->assertEquals("<", $this->windowsCodec->decode("^<"));
    }

}