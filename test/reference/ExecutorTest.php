<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2010 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author  Andrew van der Stock <vanderaj @ owasp.org>
 * @author  Linden Darling <linden.darling@jds.net.au>
 * @created 2009
 */
require_once dirname(__FILE__) . '/../../src/ESAPI.php';
require_once dirname(__FILE__) . '/../../src/errors/ExecutorException.php';
require_once dirname(__FILE__) . '/../../src/reference/DefaultExecutor.php';

class ExecutorTest extends PHPUnit_Framework_TestCase
{
    private $os;
    private $instance;

    private $executable;
    private $params;
    private $workdir;

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
            $this->executable = '%SYSTEMROOT%\\System32\\cmd.exe';
            $this->params = array("/C", "dir");
            $this->workdir = '%SYSTEMROOT%\\Temp';
        } else {
            $this->os = self::PLATFORM_UNIX;
            $this->executable = '/bin/sh';
            $this->params = array("-c", "'ls /'");
            $this->workdir = '/tmp';
        }

        $this->instance = new DefaultExecutor();
    }

    public function tearDown()
    {

    }

    /**
     * Test of executeSystemCommand method, of Executor
     */
    public function testExecuteWindowsLegalSystemCommand()
    {
        if ($this->os != self::PLATFORM_WINDOWS) {
            $this->markTestSkipped('Not Windows.');
        }

        try {
            $result = $this->instance->executeSystemCommand($this->executable, $this->params);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }

    /**
     * Test to ensure that bad commands fail
     */
    public function testExecuteWindowsInjectIllegalSystemCommand()
    {
        if ($this->os != self::PLATFORM_WINDOWS) {
            $this->markTestSkipped('Not Windows.');
        }

        $this->setExpectedException('ExecutorException');

        $this->executable = '%SYSTEMROOT%\\System32\\;notepad.exe';
        $result = $this->instance->executeSystemCommand($this->executable, $this->params);
        $this->fail('Should not execute non-canonicalized path');
    }

    /**
     * Test of file system canonicalization
     */
    public function testExecuteWindowsCanonicalization()
    {
        if ($this->os != self::PLATFORM_WINDOWS) {
            $this->markTestSkipped('Not Windows.');
        }

        $this->setExpectedException('ExecutorException');

        $this->executable = '%SYSTEMROOT%\\System32\\..\\cmd.exe';
        $result = $this->instance->executeSystemCommand($this->executable, $this->params);
        $this->fail('Should not execute non-canonicalized path');
    }

    /**
     *    Test to see if a good work directory is properly handled.
     */
    public function testExecuteWindowsGoodWorkDirectory()
    {
        if ($this->os != self::PLATFORM_WINDOWS) {
            $this->markTestSkipped('Not Windows.');
        }

        try {
            $result = $this->instance->executeSystemCommandLonghand(
                $this->executable,
                $this->params,
                $this->workdir,
                false
            );
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }


    /**
     *    Test to see if a non-existent work directory is properly handled.
     */
    public function testExecuteWindowsBadWorkDirectory()
    {
        if ($this->os != self::PLATFORM_WINDOWS) {
            $this->markTestSkipped('Not Windows.');
        }

        $this->setExpectedException('ExecutorException');

        $this->workdir = 'C:\\ridiculous';
        $result = $this->instance->executeSystemCommandLonghand(
            $this->executable,
            $this->params,
            $this->workdir,
            false
        );
        $this->fail('Should not execute with a bad working directory');
    }

    /**
     * Test to prevent chained command execution
     */
    public function testExecuteWindowsChainedCommand()
    {
        if ($this->os != self::PLATFORM_WINDOWS) {
            $this->markTestSkipped('Not Windows.');
        }

        $this->setExpectedException('ExecutorException');

        $this->executable .= " & dir & rem ";
        $result = $this->instance->executeSystemCommand($this->executable, $this->params);
        $this->fail("Executed chained command, output: " . $result);
    }

    /**
     * Test to prevent chained command execution
     */
    public function testExecuteWindowsChainedParameter()
    {
        if ($this->os != self::PLATFORM_WINDOWS) {
            $this->markTestSkipped('Not Windows.');
        }

        try {
            $this->params[] = "&dir";
            $result = $this->instance->executeSystemCommand($this->executable, $this->params);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }

    /*
    *	Test to see if the escaping mechanism renders supplemental results safely
    */
    public function testExecuteWindowsDoubleArgs()
    {
        if ($this->os != self::PLATFORM_WINDOWS) {
            $this->markTestSkipped('Not Windows.');
        }

        try {
            $this->params[] = "c:\\autoexec.bat c:\\config.sys";
            $result = $this->instance->executeSystemCommand($this->executable, $this->params);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }


    /**
     * Test of executeSystemCommand method, of Executor
     */
    public function testExecuteUnixLegalSystemCommand()
    {
        if ($this->os != self::PLATFORM_UNIX) {
            $this->markTestSkipped('Not Unix.');
        }

        try {
            $result = $this->instance->executeSystemCommand($this->executable, $this->params);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }

    /**
     * Test to ensure that bad commands fail
     */
    public function testExecuteUnixInjectIllegalSystemCommand()
    {
        if ($this->os != self::PLATFORM_UNIX) {
            $this->markTestSkipped('Not Unix.');
        }

        $this->setExpectedException('ExecutorException');

        $this->executable .= ';./inject';
        $result = $this->instance->executeSystemCommand($this->executable, $this->params);
        $this->fail('Should not have executed injected command');
    }

    /**
     * Test of file system canonicalization
     */
    public function testExecuteUnixCanonicalization()
    {
        if ($this->os != self::PLATFORM_UNIX) {
            $this->markTestSkipped('Not Unix.');
        }

        $this->setExpectedException('ExecutorException');

        $this->executable = '/bin/sh/../bin/sh';
        $result = $this->instance->executeSystemCommand($this->executable, $this->params);
        $this->fail('Should not have executed uncanonicalized command');
    }

    /**
     *    Test to see if a good work directory is properly handled.
     */
    public function testExecuteUnixGoodWorkDirectory()
    {
        if ($this->os != self::PLATFORM_UNIX) {
            $this->markTestSkipped('Not Unix.');
        }

        try {
            $result = $this->instance->executeSystemCommandLonghand(
                $this->executable,
                $this->params,
                $this->workdir,
                false
            );
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }

    /**
     *    Test to see if a non-existent work directory is properly handled.
     */
    public function testExecuteUnixBadWorkDirectory()
    {
        if ($this->os != self::PLATFORM_UNIX) {
            $this->markTestSkipped('Not Unix.');
        }

        $this->setExpectedException('ExecutorException');

        $this->workdir = '/ridiculous/';
        $result = $this->instance->executeSystemCommandLonghand(
            $this->executable,
            $this->params,
            $this->workdir,
            false
        );
        $this->fail('Bad working directory should not work.');
    }

    /**
     * Test to prevent chained command execution
     */
    public function testExecuteUnixChainedCommand()
    {
        if ($this->os != self::PLATFORM_UNIX) {
            $this->markTestSkipped('Not Unix.');
        }

        $this->setExpectedException('ExecutorException');

        $this->executable .= " ; ls / ; # ";
        $result = $this->instance->executeSystemCommand($this->executable, $this->params);
        $this->fail("Executed chained command, output: " . $result);
    }

    /**
     * Test to prevent chained command execution by adding a new command to end of the parameters
     */
    public function testExecuteUnixChainedParameter()
    {
        if ($this->os != self::PLATFORM_UNIX) {
            $this->markTestSkipped('Not Unix.');
        }

        try {
            $this->params[] = ";ls";
            $result = $this->instance->executeSystemCommand($this->executable, $this->params);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }

}