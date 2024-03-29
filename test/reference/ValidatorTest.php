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
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author  Andrew van der Stock (vanderaj @ owasp.org)
 * @created 2009
 */


require_once dirname(__FILE__) . '/../../src/ESAPI.php';
require_once dirname(__FILE__) . '/../../src/reference/DefaultValidator.php';
require_once dirname(__FILE__) . '/../testresources/TestHelpers.php';
// require_once dirname(__FILE__).'/HTTPUtilitiesTest.php';


class ValidatorTest extends PHPUnit_Framework_TestCase
{
    private $os;

    const PLATFORM_WINDOWS = 1;
    const PLATFORM_UNIX = 2;

    public function setUp()
    {
        global $ESAPI;
        if (!isset($ESAPI)) {
            $ESAPI = new ESAPI();
        }

        if (substr(PHP_OS, 0, 3) == 'WIN') {
            $this->os = self::PLATFORM_WINDOWS;
        } else {
            $this->os = self::PLATFORM_UNIX;
        }
    }

    public function tearDown()
    {
    }

    /**
     * Test isValidInput method of class Validator with a valid type: Email.
     */
    public function testIsValidInput_Email_valid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidInput('test', 'jeff.williams@aspectsecurity.com', 'Email', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with a valid type: Email.
     */
    public function testIsValidInput_Email_valid_02()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidInput('test', null, 'Email', 100, true));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type: Email.
     */
    public function testIsValidInput_Email_invalid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', 'jeff.williams@@aspectsecurity.com', 'Email', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type: Email.
     */
    public function testIsValidInput_Email_invalid_02()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', 'jeff.williams@aspectsecurity', 'Email', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type: Email.
     */
    public function testIsValidInput_Email_invalid_03()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', null, 'Email', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with a valid type:
     * IPv4 Address.
     */
    public function testIsValidInput_IPv4Address_valid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidInput('test', '123.168.100.234', 'IPAddress', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with a valid type:
     * IPv4 Address.
     */
    public function testIsValidInput_IPv4Address_valid_02()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidInput('test', '192.168.1.234', 'IPAddress', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type:
     * IPv4 Address.
     */
    public function testIsValidInput_IPv4Address_invalid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', '..168.1.234', 'IPAddress', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type:
     * IPv4 Address.
     */
    public function testIsValidInput_IPv4Address_invalid_02()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', '10.x.1.234', 'IPAddress', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with a valid type: URL.
     */
    public function testIsValidInput_URL_valid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidInput('test', 'http://www.aspectsecurity.com', 'URL', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type: URL.
     */
    public function testIsValidInput_URL_invalid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', 'http:///www.aspectsecurity.com', 'URL', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type: URL.
     */
    public function testIsValidInput_URL_invalid_02()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', 'http://www.aspect security.com', 'URL', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with a valid type:
     * US Social Security Number.
     */
    public function testIsValidInput_SSN_valid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidInput('test', '078-05-1120', 'SSN', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with a valid type:
     * US Social Security Number.
     */
    public function testIsValidInput_SSN_valid_02()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidInput('test', '078 05 1120', 'SSN', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with a valid type:
     * US Social Security Number.
     */
    public function testIsValidInput_SSN_valid_03()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidInput('test', '078051120', 'SSN', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type:
     * US Social Security Number.
     */
    public function testIsValidInput_SSN_invalid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', '987-65-4320', 'SSN', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type:
     * US Social Security Number.
     */
    public function testIsValidInput_SSN_invalid_02()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', '000-00-0000', 'SSN', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type:
     * US Social Security Number.
     */
    public function testIsValidInput_SSN_invalid_03()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', '(555) 555-5555', 'SSN', 100, false));
    }

    /**
     * Test isValidInput method of class Validator with an invalid type:
     * US Social Security Number.
     */
    public function testIsValidInput_SSN_invalid_04()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidInput('test', 'test', 'SSN', 100, false));
    }

    /**
     * Test assertValidInput method of class Validator with a valid type: Email.
     */
    public function testAssertValidInput_Email_valid_01()
    {
        $this->markTestIncomplete();

        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidInput('test', 'jeff.williams@aspectsecurity.com', 'Email', 100, false);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test assertValidInput method of class Validator with a valid type: Email.
     */
    public function testAssertValidInput_Email_valid_02()
    {
        $this->markTestIncomplete();

        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidInput('test', null, 'Email', 100, true);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test assertValidInput method of class Validator with an invalid type: Email.
     */
    public function testAssertValidInput_Email_invalid_01()
    {
        $this->markTestIncomplete();

        $instance = ESAPI::getValidator();
        $this->setExpectedException('ValidationException');
        $instance->assertValidInput('test', 'jeff.williams@@aspectsecurity.com', 'Email', 100, false);
    }

    /**
     * Test assertValidInput method of class Validator with an invalid type: Email.
     */
    public function testAssertValidInput_Email_invalid_02()
    {
        $this->markTestIncomplete();

        $instance = ESAPI::getValidator();
        $this->setExpectedException('ValidationException');
        $instance->assertValidInput('test', 'jeff.williams@aspectsecurity', 'Email', 100, false);
    }

    /**
     * Test assertValidInput method of class Validator with an invalid type: Email.
     */
    public function testAssertValidInput_Email_invalid_03()
    {
        $this->markTestIncomplete();

        $instance = ESAPI::getValidator();
        $this->setExpectedException('ValidationException');
        $instance->assertValidInput('test', null, 'Email', 100, false);
    }

    /**
     * Test assertValidInput method of class Validator with a valid type:
     * IPv4 Address.
     */
    public function testAssertValidInput_IPv4Address_valid_01()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidInput('test', '123.168.100.234', 'IPAddress', 100, false);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test assertValidInput method of class Validator with a valid type:
     * IPv4 Address.
     */
    public function testAssertValidInput_IPv4Address_valid_02()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidInput('test', '192.168.1.234', 'IPAddress', 100, false);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test assertValidInput method of class Validator with an invalid type:
     * IPv4 Address.
     */
    public function testAssertValidInput_IPv4Address_invalid_01()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        $this->setExpectedException('ValidationException');
        $instance->assertValidInput('test', '..168.1.234', 'IPAddress', 100, false);
    }

    /**
     * Test assertValidInput method of class Validator with an invalid type:
     * IPv4 Address.
     */
    public function testAssertValidInput_IPv4Address_invalid_02()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        $this->setExpectedException('ValidationException');
        $instance->assertValidInput('test', '10.x.1.234', 'IPAddress', 100, false);
    }

    /**
     * Test assertValidInput method of class Validator with a valid type: URL.
     */
    public function testAssertValidInput_URL_valid_01()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidInput('test', 'http://www.aspectsecurity.com', 'URL', 100, false);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test assertValidInput method of class Validator with an invalid type: URL.
     */
    public function testAssertValidInput_URL_invalid_01()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        $this->setExpectedException('ValidationException');
        $instance->assertValidInput('test', 'http:///www.aspectsecurity.com', 'URL', 100, false);
    }

    /**
     * Test assertValidInput method of class Validator with an invalid type: URL.
     */
    public function testAssertValidInput_URL_invalid_02()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        $this->setExpectedException('ValidationException');
        $instance->assertValidInput('test', 'http://www.aspect security.com', 'URL', 100, false);
    }

    /**
     * Test assertValidInput method of class Validator with a valid type:
     * US Social Security Number.
     */
    public function testAssertValidInput_SSN_valid_01()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidInput('test', '078-05-1120', 'SSN', 100, false);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test assertValidInput method of class Validator with a valid type:
     * US Social Security Number.
     */
    public function testAssertValidInput_SSN_valid_02()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidInput('test', '078 05 1120', 'SSN', 100, false);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test assertValidInput method of class Validator with a valid type:
     * US Social Security Number.
     */
    public function testAssertValidInput_SSN_valid_03()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidInput('test', '078051120', 'SSN', 100, false);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test of isValidDate method of class Validator with an valid date.
     */
    public function testIsValidDate_valid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue($instance->isValidDate('testIsValidDate_valid_01', 'June 23, 1967', 'F j, Y', false));
    }

    /**
     * Test of isValidDate method of class Validator with an invalid date.
     */
    public function testIsValidDate_invalid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse($instance->isValidDate('testIsValidDate_invalid_01', 'freakshow', 'F j, Y', false));
    }

    /**
     * Test of assertValidDate method of class Validator with an valid date.
     */
    public function testAssertValidDate_valid_01()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        try {
            $instance->assertValidDate('testAssertValidDate_valid_01', 'June 23, 1967', 'F j, Y', false);
        } catch (Exception $e) {
            $this->fail();
        }
    }

    /**
     * Test of assertValidDate method of class Validator with an invalid date.
     */
    public function testAssertValidDate_invalid_01()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();
        $this->setExpectedException('ValidationException');
        $instance->assertValidDate('testAssertValidDate_invalid_01', 'freakshow', 'F j, Y', false);
    }

    /**
     * Test of isValidSafeHTML method, of class org.owasp.esapi.Validator.
     */
    public function testIsValidSafeHTML()
    {
        $this->markTestIncomplete();
        $instance = ESAPI::getValidator();

        $this->assertTrue($instance->isValidSafeHTML('test', '<b>Jeff</b>', 100, false));
        $this->assertTrue(
            $instance->isValidSafeHTML(
                'test', "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false
            )
        );
        $this->assertFalse(
            $instance->isValidSafeHTML('test', 'Test. <script>alert(document.cookie)</script>', 100, false)
        );

        // TODO: waiting for a way to validate text headed for an attribute for scripts
        // This would be nice to catch, but just looks like text to AntiSamy
        // $this->assertFalse($instance->isValidSafeHTML('test', "\" onload=\"alert(document.cookie)\" "));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with a valid CC number.
     */
    public function testIsValidCreditCard_valid_01()
    {
        $val = ESAPI::getValidator();
        $this->assertTrue($val->isValidCreditCard('testIsValidCreditCard_valid_01', '1234 9876 0000 0008', false));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with a valid CC number.
     */
    public function testIsValidCreditCard_valid_02()
    {
        $val = ESAPI::getValidator();
        $this->assertTrue($val->isValidCreditCard('testIsValidCreditCard_valid_02', '1234987600000008', false));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with a valid CC number.
     */
    public function testIsValidCreditCard_valid_03()
    {
        $val = ESAPI::getValidator();
        $this->assertTrue($val->isValidCreditCard('testIsValidCreditCard_valid_03', '1234-9876-0000-0008', false));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with valid allowable
     * null.
     */
    public function testIsValidCreditCard_valid_04()
    {
        $val = ESAPI::getValidator();
        $this->assertTrue($val->isValidCreditCard('testIsValidCreditCard_valid_04', '', true));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with valid allowable
     * null.
     */
    public function testIsValidCreditCard_valid_05()
    {
        $val = ESAPI::getValidator();
        $this->assertTrue($val->isValidCreditCard('testIsValidCreditCard_valid_05', null, true));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with an invalid CC number.
     */
    public function testIsValidCreditCard_invalid_01()
    {
        $val = ESAPI::getValidator();
        $this->assertFalse($val->isValidCreditCard('testIsValidCreditCard_invalid_01', '12349876000000081', false));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with an invalid CC number.
     */
    public function testIsValidCreditCard_invalid_02()
    {
        $val = ESAPI::getValidator();
        $this->assertFalse($val->isValidCreditCard('testIsValidCreditCard_invalid_02', '4417 1234 5678 9112', false));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with allowable null.
     */
    public function testIsValidCreditCard_invalid_06()
    {
        $val = ESAPI::getValidator();
        $this->assertFalse($val->isValidCreditCard('testIsValidCreditCard_valid_06', 0, true));
    }

    /**
     * Test of isValidEmailCreditCard method of Validator with allowable null.
     */
    public function testIsValidCreditCard_invalid_07()
    {
        $val = ESAPI::getValidator();
        $this->assertFalse($val->isValidCreditCard('testIsValidCreditCard_valid_07', array(), true));
    }

    /**
     * Test of isValidListItem method, of class org.owasp.esapi.Validator.
     */
    public function testIsValidListItem()
    {
        $val = ESAPI::getValidator();
        $list = array('one', 'two');
        $this->assertTrue($val->isValidListItem('test', 'one', $list));
        $this->assertFalse($val->isValidListItem('test', 'three', $list));
    }

    /**
     * Test of isValidNumber method, of class org.owasp.esapi.Validator.
     */
    public function testIsValidNumber()
    {
        $instance = ESAPI::getValidator();
//        testing negative range
        $this->assertFalse($instance->isValidNumber('test', '-4', 1, 10, false));
        $this->assertTrue($instance->isValidNumber('test', '-4', -10, 10, false));
//        //testing null value
        $this->assertTrue($instance->isValidNumber('test', null, -10, 10, true));
        $this->assertFalse($instance->isValidNumber('test', null, -10, 10, false));
//        //testing empty string
        $this->assertTrue($instance->isValidNumber('test', '', -10, 10, true));
        $this->assertFalse($instance->isValidNumber('test', '', -10, 10, false));
//        //testing improper range
        $this->assertFalse($instance->isValidNumber('test', '5', 10, -10, false));
//        //testing non-integers
        $this->assertTrue($instance->isValidNumber('test', '4.3214', -10, 10, true));
        $this->assertTrue($instance->isValidNumber('test', '-1.65', -10, 10, true));
//        //other testing
        $this->assertTrue($instance->isValidNumber('test', '4', 1, 10, false));
        $this->assertTrue($instance->isValidNumber('test', '400', 1, 10000, false));
        $this->assertTrue($instance->isValidNumber('test', '400000000', 1, 400000000, false));
        $this->assertFalse($instance->isValidNumber('test', '4000000000000', 1, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', 'alsdkf', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '--10', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '14.1414234x', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', 'Infinity', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '-Infinity', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', 'NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '-NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '+NaN', 10, 10000, false));
        $this->assertTrue($instance->isValidNumber('test', '1e-6', -999999999, 999999999, false));
        $this->assertTrue($instance->isValidNumber('test', '-1e-6', -999999999, 999999999, false));
    }

    public function testIsValidInteger()
    {
        $instance = ESAPI::getValidator();
        //testing negative range
        $this->assertFalse($instance->isValidInteger('test', '-4', 1, 10, false));
        $this->assertTrue($instance->isValidInteger('test', '-4', -10, 10, false));
        //testing null value
        $this->assertTrue($instance->isValidInteger('test', null, -10, 10, true));
        $this->assertFalse($instance->isValidInteger('test', null, -10, 10, false));
        //testing empty string
        $this->assertTrue($instance->isValidInteger('test', '', -10, 10, true));
        $this->assertFalse($instance->isValidInteger('test', '', -10, 10, false));
        //testing improper range
        $this->assertFalse($instance->isValidInteger('test', '5', 10, -10, false));
        //testing non-integers
        $this->assertFalse($instance->isValidInteger('test', '4.3214', -10, 10, true));
        $this->assertFalse($instance->isValidInteger('test', '-1.65', -10, 10, true));
        //other testing
        $this->assertTrue($instance->isValidInteger('test', '4', 1, 10, false));
        $this->assertTrue($instance->isValidInteger('test', '400', 1, 10000, false));
        $this->assertTrue($instance->isValidInteger('test', '400000000', 1, 400000000, false));
        $this->assertFalse($instance->isValidInteger('test', '4000000000000', 1, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', 'alsdkf', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '--10', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '14.1414234x', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', 'Infinity', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '-Infinity', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', 'NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '-NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '+NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '1e-6', -999999999, 999999999, false));
        $this->assertFalse($instance->isValidInteger('test', '-1e-6', -999999999, 999999999, false));
    }

    /**
     * Test isValidPrintable method of class Validator with a valid input.
     */
    public function testIsValidPrintable_valid_01()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue(
            $instance
                ->isValidPrintable('test', 'abcDEF', 100, false)
        );
    }

    /**
     * Test isValidPrintable method of class Validator with a valid input.
     */
    public function testIsValidPrintable_valid_02()
    {
        $input = '';
        for ($i = 32; $i <= 126; $i++) {
            $input .= chr($i);
        }
        $instance = ESAPI::getValidator();
        $this->assertTrue(
            $instance
                ->isValidPrintable('test', $input, 100, false)
        );
    }

    /**
     * Test isValidPrintable method of class Validator with a valid input.
     */
    public function testIsValidPrintable_valid_03()
    {
        $instance = ESAPI::getValidator();
        $this->assertTrue(
            $instance
                ->isValidPrintable('test', '!@#R()*$;><()', 100, false)
        );
    }

    /**
     * Test isValidPrintable method of class Validator with an invalid input.
     */
    public function testIsValidPrintable_invalid_01()
    {
        $bytes = chr(0x60) . chr(0xFF) . chr(0x10) . chr(0x25);
        $instance = ESAPI::getValidator();
        $this->assertFalse(
            $instance
                ->isValidPrintable('test', $bytes, 100, false)
        );
    }

    /**
     * Test isValidPrintable method of class Validator with an invalid input.
     */
    public function testIsValidPrintable_invalid_02()
    {
        $instance = ESAPI::getValidator();
        $this->assertFalse(
            $instance
                ->isValidPrintable('test', '%08', 100, false)
        );
    }

    /**
     * Test of isValidDirectoryPath method, of class org.owasp.esapi.Validator.
     */
    public function testIsValidDirectoryPath()
    {
        $list = array();
        array_push($list, new HTMLEntityCodec());
        $encoder = new DefaultEncoder($list);
        $instance = ESAPI::getValidator();

        switch ($this->os) {
            case self::PLATFORM_WINDOWS:
                // Windows paths that don't exist and thus should fail
                $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\ridiculous', false));
                $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\jeff', false));
                $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\temp\\..\\etc', false));

                // Windows paths that should pass
                $this->assertTrue($instance->isValidDirectoryPath('test', 'C:\\', false)); // Windows root directory
                $this->assertTrue(
                    $instance->isValidDirectoryPath('test', 'C:\\Windows', false)
                ); // Windows always exist directory
                $this->assertTrue(
                    $instance->isValidDirectoryPath('test', 'C:\\Windows\\System32\\cmd.exe', false)
                ); // Windows command shell

                // Unix specific paths should not pass
                $this->assertFalse($instance->isValidDirectoryPath('test', '/tmp', false)); // Unix Temporary directory
                $this->assertFalse($instance->isValidDirectoryPath('test', '/bin/sh', false)); // Unix Standard shell
                $this->assertFalse($instance->isValidDirectoryPath('test', '/etc/config', false));

                // Unix specific paths that should not exist or work
                $this->assertFalse($instance->isValidDirectoryPath('test', '/etc/ridiculous', false));
                $this->assertFalse($instance->isValidDirectoryPath('test', '/tmp/../etc', false));
                break;
            case self::PLATFORM_UNIX:
                // Windows paths should fail
                $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\ridiculous', false));
                $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\temp\\..\\etc', false));

                // Standard Windows locations should fail
                $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\', false)); // Windows root directory
                $this->assertFalse(
                    $instance->isValidDirectoryPath('test', 'c:\\Windows\\temp', false)
                ); // Windows temporary directory
                $this->assertFalse(
                    $instance->isValidDirectoryPath('test', 'c:\\Windows\\System32\\cmd.exe', false)
                ); // Windows command shell

                // Unix specific paths should pass
                $this->assertTrue($instance->isValidDirectoryPath('test', '/', false)); // Root directory
                $this->assertTrue($instance->isValidDirectoryPath('test', '/bin', false)); // Always exist directory
                $this->assertTrue($instance->isValidDirectoryPath('test', '/bin/sh', false)); // Standard shell

                // Unix specific paths that should not exist or work
                $this->assertFalse($instance->isValidDirectoryPath('test', '/etc/ridiculous', false));
                $this->assertFalse($instance->isValidDirectoryPath('test', '/tmp/../etc', false));

                break;
            default:
                $this->fail("No platform support for your platform.");
                break;
        }
    }
}

