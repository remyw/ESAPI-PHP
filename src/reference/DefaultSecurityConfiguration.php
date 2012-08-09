<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project.
 *
 * PHP version 5.2
 *
 * LICENSE: This source file is subject to the New BSD license.  You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 *
 * @category  OWASP
 * @package   ESAPI_Reference
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   SVN: $Id$
 * @link      http://www.owasp.org/index.php/ESAPI
 */

require_once dirname(__FILE__) . '/../SecurityConfiguration.php';

/**
 * Reference Implementation of the SecurityConfiguration interface.
 *
 * @category  OWASP
 * @package   ESAPI_Reference
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class DefaultSecurityConfiguration implements SecurityConfiguration
{
    // SimpleXML reads the entire file into memory
    private $xml = null;

    // Authenticator
    private $rememberTokenDuration = null;
    private $allowedLoginAttempts = null;
    private $maxOldPasswordHashes = null;
    private $usernameParameterName = null;
    private $passwordParameterName = null;
    private $idleTimeoutDuration = null;
    private $absoluteTimeoutDuration = null;

    // Executor
    private $allowedExecutables = null;
    private $workingDirectory = null;

    // Encryptor
    private $characterEncoding = null;
    private $masterKey = null;
    private $masterSalt = null;
    private $encryptionAlgorithm = null;
    private $hashAlgorithm = null;
    private $digitalSignatureAlgorithm = null;
    private $randomAlgorithm = null;

    // HTTPUtilities
    private $allowedFileExtensions = null;
    private $maxUploadSize = null;
    private $responseContentType = null;
    private $allowedIncludes = null;
    private $allowedResources = null;

    // Logger
    private $applicationName = null;
    private $logApplicationName = null;
    private $logEncodingRequired = null;
    private $logLevel = null;
    private $logFileName = null;
    private $maxLogFileSize = null;
    private $maxLogFileBackups = null;
    private $logFileDateFormat = null;

    // Validator
    private $patternCache = array();

    // IntrusionDetector
    private $disableIntrusionDetection = null;
    private $events = null;
    private $resourceDir = null;

    // Special Debugging
    private $specialDebugging = null;

    /**
     * SecurityConfiguration constructor.
     *
     * @param string $path configuration file path.
     *
     * @return does not return a value.
     */
    public function __construct($path = '')
    {
        try {
            $this->loadConfiguration($path);
            $this->setResourceDirectory(dirname(realpath($path)));
        } catch (Exception $e) {
            $this->logSpecial($e->getMessage());
        }
    }

    /**
     * Helper function.
     *
     * @param string $path ESAPI configuration file path.
     *
     * @return does not return a value.
     * @throws Exception thrown if configuration file does not exist.
     */
    private function loadConfiguration($path)
    {
        if (file_exists($path)) {
            $this->xml = simplexml_load_file($path);

            if ($this->xml === false) {
                throw new Exception("Failed to load security configuration.");
            }
        } else {
            throw new Exception("Security configuration file does not exist.");
        }
    }

    /**
     * Helper function.
     *
     * @return bool TRUE, if able to load events.
     */
    private function loadEvents()
    {
        $_events = $this->xml->xpath('/esapi-properties/IntrusionDetector/event');

        if ($_events === false) {
            $this->events = null;
            $this->logSpecial(
                'SecurityConfiguration for ' .
                    '/esapi-properties/IntrusionDetector/event not found in ESAPI.xml.'
            );
            return false;
        }

        $this->events = array();

        // Cycle through each event
        foreach ($_events as $event) {
            // Obtain data for the event

            $name = (string)$event->attributes()->name;
            $count = (int)$event->attributes()->count;
            $interval = (int)$event->attributes()->interval;

            $actions = array();
            foreach ($event->action as $node) {
                $actions[] = (string)$node;
            }

            // Validate the event

            if (!empty($name) && $count > 0 && $interval > 0 && !empty($actions)) {
                // Add a new threshold object to $events array
                $this->events[] = new Threshold(
                    $name, $count, $interval, $actions
                );
            }
        }

        if (count($this->events) == 0) {
            $this->events = null;
            $this->logSpecial(
                'SecurityConfiguration found no valid events in ' .
                    'the Intrusion Detection section.'
            );
            return false;
        }

        return true;
    }

    /**
     * Helper function.
     *
     * @param string $msg Message to output to the console.
     *
     * @return does not return a value.
     */
    private function logSpecial($msg)
    {
        echo $msg;
    }

    /**
     * Helper function.
     *
     * @param string $prop Property name.
     * @param string $def  Default value.
     *
     * @return string property name if found, default value otherwise.
     */
    private function getESAPIStringProperty($prop, $def)
    {
        $val = $def;

        $var = $this->xml->xpath('/esapi-properties/' . $prop);

        if ($var === false) {
            $this->logSpecial(
                'SecurityConfiguration for /esapi-properties/' .
                $prop . ' not found in ESAPI.xml. Using default: ' . $def
            );
        }

        if (isset($var[0])) {
            $val = (string)$var[0];
        }

        return $val;
    }

    /**
     * Helper function.
     *
     * @param string $prop Property name.
     * @param string $def  Default value.
     *
     * @return string property name if found, default value otherwise.
     */
    private function getESAPIArrayProperty($prop, $def)
    {
        $val = $def;

        $var = $this->xml->xpath('/esapi-properties/' . $prop);

        if ($var === false) {
            $this->logSpecial(
                'SecurityConfiguration for /esapi-properties/' .
                $prop . ' not found in ESAPI.xml. Using default: ' . $def
            );
        }

        $result = array();
        if (isset($var)) {
            foreach ($var as $node) {
                $result[] = (string)$node;
            }

            $val = $result;
        }

        return $val;
    }

    /**
     * Helper function.
     *
     * @param string $type Regex name.
     *
     * @return string property name if found, default value otherwise.
     */
    private function getESAPIValidationExpression($type)
    {
        $val = null;
        $found = false;
        $i = 0;

        $var = $this->xml->xpath('//regexp');

        if ($var === false) {
            $this->logSpecial(
                'getESAPIValidationExpression: No regular ' .
                'expressions in the config file.'
            );
            return false;
        }

        if (isset($var[0])) {
            while (list(, $node) = each($var)) {
                $result[] = (string)$node;

                foreach ($node->attributes() as $a => $b) {
                    if (!strcmp($a, "name")) {
                        if (!strcmp((string)$b, $type)) {
                            $val = $var[$i];
                            $found = true;
                            break 2;
                        }
                    }
                }
                $i++;
            }
        }

        if ($found && isset($val->attributes()->value)) {
            return (string)$val->attributes()->value;
        } else {
            $this->logSpecial(
                'getESAPIValidationExpression: Cannot find ' .
                'regular expression: ' . $type
            );
            return false;
        }
    }

    /**
     * Helper function.
     *
     * @param string $prop Property name.
     * @param string $def  Default value.
     *
     * @return string property name if found, default value otherwise.
     */
    private function getESAPIEncodedStringProperty($prop, $def)
    {
        return base64_decode($this->getESAPIStringProperty($prop, $def));
    }

    /**
     * Helper function.
     *
     * @param string $prop Property name.
     * @param string $def  Default value.
     *
     * @return string property name if found, default value otherwise.
     */
    private function getESAPIIntProperty($prop, $def)
    {
        $val = $def;

        $var = $this->xml->xpath('/esapi-properties/' . $prop);

        if ($var === false) {
            $this->logSpecial(
                'SecurityConfiguration for /esapi-properties/' .
                $prop . ' not found in ESAPI.xml. Using default: ' . $def
            );
        }

        if (isset($var[0])) {
            $val = (int)$var[0];
        }

        return (string)$val;
    }

    /**
     * Helper function.
     *
     * @param string $prop Property name.
     * @param string $def  Default value.
     *
     * @return string property name if found, default value otherwise.
     */
    private function getESAPIBooleanProperty($prop, $def)
    {
        $val = $this->getESAPIStringProperty($prop, $def);

        if ($val !== $def) {
            $val = (strtolower($val) == "false") ? false : true;
        }

        return $val;
    }

    /**
     * @inheritdoc
     */
    public function getApplicationName()
    {
        if ($this->applicationName === null) {
            $this->applicationName = $this->getESAPIStringProperty(
                "Logger/ApplicationName",
                'DefaultName'
            );
        }

        return $this->applicationName;
    }

    /**
     * @inheritdoc
     */
    public function getRememberTokenDuration()
    {
        if ($this->rememberTokenDuration === null) {
            $this->rememberTokenDuration = $this->getESAPIIntProperty(
                "Authenticator/RememberTokenDuration",
                14
            );
        }

        return $this->rememberTokenDuration * 1000 * 60 * 60 * 24;
    }

    /**
     * @inheritdoc
     */
    public function getAllowedLoginAttempts()
    {
        if ($this->allowedLoginAttempts === null) {
            $this->allowedLoginAttempts = $this->getESAPIIntProperty(
                "Authenticator/AllowedLoginAttempts",
                5
            );
        }

        return $this->allowedLoginAttempts;
    }

    /**
     * @inheritdoc
     */
    public function getMaxOldPasswordHashes()
    {
        if ($this->maxOldPasswordHashes === null) {
            $this->maxOldPasswordHashes = $this->getESAPIIntProperty(
                "Authenticator/MaxOldPasswordHashes",
                12
            );
        }

        return $this->maxOldPasswordHashes;
    }

    /**
     * @inheritdoc
     */
    public function getPasswordParameterName()
    {
        if ($this->passwordParameterName === null) {
            $this->passwordParameterName = $this->getESAPIStringProperty(
                "Authenticator/PasswordParameterName",
                'password'
            );
        }

        return $this->passwordParameterName;
    }

    /**
     * @inheritdoc
     */
    public function getUsernameParameterName()
    {
        if ($this->usernameParameterName === null) {
            $this->usernameParameterName = $this->getESAPIStringProperty(
                "Authenticator/UsernameParameterName",
                'username'
            );
        }

        return $this->usernameParameterName;
    }

    /**
     * @inheritdoc
     */
    public function getSessionIdleTimeoutLength()
    {
        if ($this->idleTimeoutDuration === null) {
            $this->idleTimeoutDuration = $this->getESAPIIntProperty(
                "Authenticator/IdleTimeoutDuration",
                20
            );
        }

        return $this->idleTimeoutDuration * 1000 * 60;
    }

    /**
     * @inheritdoc
     */
    public function getSessionAbsoluteTimeoutLength()
    {
        if ($this->absoluteTimeoutDuration === null) {
            $this->absoluteTimeoutDuration = $this->getESAPIIntProperty(
                "Authenticator/AbsoluteTimeoutDuration",
                20
            );
        }

        return $this->absoluteTimeoutDuration * 1000 * 60;
    }

    /**
     * @inheritdoc
     */
    public function getMasterKey()
    {
        if ($this->masterKey === null) {
            $this->masterKey = $this->getESAPIEncodedStringProperty(
                "Encryptor/secrets/MasterKey",
                null
            );
        }

        return $this->masterKey;
    }

    /**
     * @inheritdoc
     */
    public function getMasterSalt()
    {
        if ($this->masterSalt === null) {
            $this->masterSalt = $this->getESAPIEncodedStringProperty(
                "Encryptor/secrets/MasterSalt",
                null
            );
        }

        return $this->masterSalt;
    }

    /**
     * @inheritdoc
     */
    public function getAllowedFileExtensions()
    {
        if ($this->allowedFileExtensions === null) {
            $this->allowedFileExtensions = $this->getESAPIArrayProperty(
                "HttpUtilities/ApprovedUploadExtensions/extension",
                null
            );
        }

        return $this->allowedFileExtensions;
    }

    /**
     * @inheritdoc
     */
    public function getAllowedFileUploadSize()
    {
        if ($this->maxUploadSize === null) {
            $this->maxUploadSize = $this->getESAPIIntProperty(
                "HttpUtilities/maxUploadFileBytes",
                20
            );
        }

        return $this->maxUploadSize;
    }

    /**
     * @inheritdoc
     */
    public function getEncryptionAlgorithm()
    {
        if ($this->encryptionAlgorithm === null) {
            $this->encryptionAlgorithm = $this->getESAPIStringProperty(
                "Encryptor/EncryptionAlgorithm",
                'AES'
            );
        }

        return $this->encryptionAlgorithm;
    }

    /**
     * @inheritdoc
     */
    public function getHashAlgorithm()
    {
        if ($this->hashAlgorithm === null) {
            $this->hashAlgorithm = $this->getESAPIStringProperty(
                "Encryptor/HashAlgorithm",
                'SHA-512'
            );
        }

        return $this->hashAlgorithm;
    }

    /**
     * @inheritdoc
     */
    public function getCharacterEncoding()
    {
        if ($this->characterEncoding === null) {
            $this->characterEncoding = $this->getESAPIStringProperty(
                "Encryptor/CharacterEncoding",
                'UTF-8'
            );
        }

        return $this->characterEncoding;
    }

    /**
     * @inheritdoc
     */
    public function getDigitalSignatureAlgorithm()
    {
        if ($this->digitalSignatureAlgorithm === null) {
            $this->digitalSignatureAlgorithm = $this->getESAPIStringProperty(
                "Encryptor/DigitalSignatureAlgorithm",
                'DSA'
            );
        }

        return $this->digitalSignatureAlgorithm;
    }

    /**
     * @inheritdoc
     */
    public function getRandomAlgorithm()
    {
        if ($this->randomAlgorithm === null) {
            $this->randomAlgorithm = $this->getESAPIStringProperty(
                "Encryptor/RandomAlgorithm",
                'SHA1PRNG'
            );
        }

        return $this->randomAlgorithm;
    }

    /**
     * @inheritdoc
     */
    public function getQuota($eventName)
    {
        if ($eventName == null) {
            return null;
        }

        if ($this->events == null) {
            $this->loadEvents();
            if ($this->events == null) {
                return null;
            }
        }

        // Search for the event, and return it if it exists

        $theEvent = null;
        foreach ($this->events as $event) {
            if ($event->name == $eventName) {
                $theEvent = $event;
                break;
            }
        }

        return $theEvent;
    }

    /**
     * @inheritdoc
     */
    public function getDisableIntrusionDetection()
    {
        if ($this->disableIntrusionDetection === null) {
            $this->disableIntrusionDetection = $this->getESAPIBooleanProperty(
                "IntrusionDetector/DisableIntrusionDetection",
                false
            );
        }

        return $this->disableIntrusionDetection;
    }

    /**
     * @inheritdoc
     */
    public function getResourceDirectory()
    {
        return $this->resourceDir;
    }

    /**
     * @inheritdoc
     */
    public function setResourceDirectory($dir)
    {
        $this->resourceDir = $dir;
    }

    /**
     * @inheritdoc
     */
    public function getResponseContentType()
    {
        if ($this->responseContentType === null) {
            $this->responseContentType = $this->getESAPIStringProperty(
                "HttpUtilities/ResponseContentType",
                'UTF-8'
            );
        }

        return $this->responseContentType;
    }

    /**
     * @inheritdoc
     */
    public function getLogApplicationName()
    {
        if ($this->logApplicationName === null) {
            $this->logApplicationName = $this->getESAPIBooleanProperty(
                "Logger/LogApplicationName",
                false
            );
        }

        return $this->logApplicationName;
    }

    /**
     * @inheritdoc
     */
    public function getLogEncodingRequired()
    {
        if ($this->logEncodingRequired === null) {
            $this->logEncodingRequired = $this->getESAPIBooleanProperty(
                "Logger/LogEncodingRequired",
                false
            );
        }

        return $this->logEncodingRequired;
    }

    /**
     * @inheritdoc
     */
    public function getLogLevel()
    {
        if ($this->logLevel === null) {
            $this->logLevel = $this->getESAPIStringProperty(
                "Logger/LogLevel",
                'WARNING'
            );
        }

        return $this->logLevel;
    }

    /**
     * @inheritdoc
     */
    public function getLogFileName()
    {
        if ($this->logFileName === null) {
            $this->logFileName = $this->getESAPIStringProperty(
                "Logger/LogFileName",
                'ESAPI_logging_file'
            );
        }

        return $this->logFileName;
    }

    /**
     * @inheritdoc
     */
    public function getMaxLogFileSize()
    {
        if ($this->maxLogFileSize === null) {
            $this->maxLogFileSize = $this->getESAPIIntProperty(
                "Logger/MaxLogFileSize",
                10000000
            );
        }

        return $this->maxLogFileSize;
    }

    /**
     * @inheritdoc
     */
    public function getMaxLogFileBackups()
    {
        if ($this->maxLogFileBackups === null) {
            $this->maxLogFileBackups = $this->getESAPIIntProperty(
                "Logger/MaxLogFileBackups",
                10
            );
        }

        return $this->maxLogFileBackups;
    }

    /**
     * @inheritdoc
     */
    public function getLogFileDateFormat()
    {
        if ($this->logFileDateFormat === null) {
            $this->logFileDateFormat = $this->getESAPIStringProperty(
                "Logger/LogFileDateFormat",
                'Y-m-d H:i:s P'
            );
        }

        return $this->logFileDateFormat;
    }

    /**
     * @inheritdoc
     */
    public function getValidationPattern($type)
    {
        return $this->getESAPIValidationExpression($type);
    }

    /**
     * @inheritdoc
     */
    public function getWorkingDirectory()
    {
        if ($this->workingDirectory === null) {
            $path = (substr(PHP_OS, 0, 3) == 'WIN')
                ?
                'ExecutorWindows/WorkingDirectory'
                :
                'ExecutorUnix/WorkingDirectory';
            $this->workingDirectory = $this->getESAPIStringProperty($path, '');
        }

        return $this->workingDirectory;
    }

    /**
     * @inheritdoc
     */
    public function getAllowedExecutables()
    {
        if ($this->allowedExecutables === null) {
            $path = (substr(PHP_OS, 0, 3) == 'WIN')
                ?
                'ExecutorWindows/ApprovedExecutables/command'
                :
                'ExecutorUnix/ApprovedExecutables/command';
            $this->allowedExecutables = $this->getESAPIArrayProperty($path, null);
        }

        return $this->allowedExecutables;
    }

    /**
     * @inheritdoc
     */
    public function getAllowedIncludes()
    {
        if ($this->allowedIncludes === null) {
            $path = 'HttpUtilities/ApprovedIncludes/include';
            $this->allowedIncludes = $this->getESAPIArrayProperty($path, null);
        }

        return $this->allowedIncludes;
    }

    /**
     * @inheritdoc
     */
    public function getAllowedResources()
    {
        if ($this->allowedResources === null) {
            $path = 'HttpUtilities/ApprovedResources/resource';
            $this->allowedResources = $this->getESAPIArrayProperty($path, null);
        }

        return $this->allowedResources;
    }

    /**
     * getSpecialDebugging returns boolean true if special debugging should be
     * enabled. Default is false.
     * At the moment, special debugging is used for producing output from
     * CodecDebug.
     *
     * @return bool True if special debugging should be enabled. Default is false.
     */
    public function getSpecialDebugging()
    {
        if ($this->specialDebugging === null) {
            $path = 'SpecialDebugging/Enabled';
            $this->specialDebugging = $this->getESAPIBooleanProperty($path, false);
        }

        return $this->specialDebugging;
    }
}