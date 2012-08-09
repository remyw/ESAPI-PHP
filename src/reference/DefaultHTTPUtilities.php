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
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   SVN: $Id$
 * @link      http://www.owasp.org/index.php/ESAPI
 */


/**
 * DefaultHTTPUtilities requires the HTTPUtilities interface.
 */
require_once dirname(__FILE__) . '/../HTTPUtilities.php';


/**
 * Reference implementation of the HTTPUtilities interface.
 *
 * PHP version 5.2
 *
 * @category  OWASP
 * @package   ESAPI_Reference
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class DefaultHTTPUtilities implements HTTPUtilities
{

    private $auditor = null;
    private $currentRequest = null;
    private $validator = null;

    /**
     * The constructor stores an instance of Auditor for the purpose of logging.
     *
     * @return null
     */
    public function __construct()
    {
        Global $ESAPI;
        $this->auditor = ESAPI::getAuditor('DefaultHTTPUtilities');
        $this->validator = ESAPI::getValidator();
    }

    /**
     * Adds the CSRF token from the current session to the supplied URL for the
     * purposes of preventing CSRF attacks. This method should be used on all URLs
     * to be put into all links and forms the application generates.
     *
     * @param string $href the URL to which the CSRF token will be appended.
     *
     * @return string URL with the CSRF token parameter appended to it.
     */
    public function addCSRFToken($href)
    {
        if (!is_string($href) || empty($href)) {
            throw new InvalidArgumentException(
                'addCSRFToken expects string $href.'
            );
        }
        if (!isset($_SESSION)) {
            return $href;
        }

        $token = $this->getCSRFToken();
        if ($token === null) {
            return $href;
        }

        if (strpos($href, '?') === false) {
            $href .= '?' . $token;
        } else {
            $href .= '&' . $token;
        }

        return $href;
    }

    /**
     * Returns the CSRF token from the current session. If there is no current
     * session then null is returned. If the CSRF Token is not present in the
     * session it will be created.
     *
     * @return string|null CSRF token for the current session or
     *                     null.
     */
    public function getCSRFToken()
    {
        if (!isset($_SESSION)) {
            return null;
        }

        if (!array_key_exists('ESAPI', $_SESSION)
            || !array_key_exists('HTTPUtilities', $_SESSION['ESAPI'])
            || !array_key_exists('CSRFToken', $_SESSION['ESAPI']['HTTPUtilities'])
        ) {
            $this->setCSRFToken();
        }

        return $_SESSION['ESAPI']['HTTPUtilities']['CSRFToken'];
    }

    /**
     * Searches the GET and POST parameters in a request for the CSRF token stored
     * in the current session and throws an IntrusionException if it is missing.
     *
     * @param SafeRequest $request A request object.
     *
     * @return null
     *
     * @throws IntrusionException if the CSRF token is missing or incorrect.
     */
    public function verifyCSRFToken($request)
    {
        if ($request instanceof SafeRequest == false) {
            throw new InvalidArgumentException(
                'verifyCSRFToken expects an instance of SafeRequest.'
            );
        }

        if ($request->getParameter($this->getCSRFToken()) === null) {
            throw new IntrusionException(
                'Authentication failed.',
                'Possibly forged HTTP request without proper CSRF token detected.'
            );
        }

    }

    /**
     * Sets the CSRF Token for the current session.  If the session has not been
     * started at the time this method is called then the token will not be
     * generated.
     *
     * @return null
     */
    public function setCSRFToken()
    {
        if (!isset($_SESSION)) {
            return null;
        }

        if (!array_key_exists('ESAPI', $_SESSION)) {
            $_SESSION['ESAPI'] = array(
                'HTTPUtilities' => array(
                    'CSRFToken' => ''
                )
            );
        } else {
            if (!array_key_exists('HTTPUtilities', $_SESSION['ESAPI'])) {
                $_SESSION['ESAPI']['HTTPUtilities'] = array(
                    'CSRFToken' => ''
                );

            }
        }

        $_SESSION['ESAPI']['HTTPUtilities']['CSRFToken']
            = ESAPI::getRandomizer()->getRandomGUID();
    }

    /**
     * Get the first cookie with the matching name.
     *
     * @param SafeRequest $request Request object.
     * @param string      $name    The name of the cookie to retreive.
     *
     * @return string|null value of the requested cookie or
     *                     null if the specified cookie is not present.
     */
    public function getCookie($request, $name)
    {
        if ($request instanceof SafeRequest == false) {
            throw new InvalidArgumentException(
                'getCookie expects an instance of SafeRequest.'
            );
        }
        return $request->getCookie($name);
    }

    /**
     * Ensures that the supplied request was received with Transport Layer
     * Security and uses the HTTP POST to protect any sensitive parameters in
     * the request from being sniffed or logged. For example, this method should
     * be called from any method that uses sensitive data from a web form.
     *
     * @param SafeRequest $request The request object to test.
     *
     * @return null
     *
     * @throws AccessControlException if security constraints are not met.
     */
    public function assertSecureRequest($request)
    {
        if ($request instanceof SafeRequest == false) {
            throw new InvalidArgumentException(
                'assertSecureRequest expects an instance of SafeRequest.'
            );
        }

        $requiredMethod = 'POST';
        $receivedMethod = $request->getMethod();
        if ($receivedMethod !== $requiredMethod) {
            throw new AccessControlException(
                'Insecure request received',
                "Request Not Secure: Received request using {$receivedMethod} when only {$requiredMethod} is allowed."
            );
        }

        if ($this->isSecureChannel($request) != true) {
            throw new AccessControlException(
                'Your request was not sent using Transport Layer Security',
                'Request Not Secure: $_SERVER[\'HTTPS\'] was empty or off; Request was not sent over secured transport.'
            );
        }
    }

    /**
     * Invalidate the old session after copying all of its contents to a newly
     * created session with a new session id. Note that this is different from
     * logging out and creating a new session identifier that does not contain
     * the existing session contents. Care should be taken to use this only when
     * the existing session does not contain hazardous contents.
     *
     * @return bool true if the change of Session Identifier was successful,
     *              false otherwise
     */
    public function changeSessionIdentifier()
    {
        $result = session_regenerate_id(true);
        return $result;
    }

    /**
     * Returns true if the supplied request object was received over a secured
     * channel i.e. Transport Layer Security (e.g. SSL or TLS).
     * This method tests for the $_SERVER global with key 'HTTPS' which should
     * be a non-empty value if TLS was used.  Since this key is not part of the
     * CGI 1.1 specification there is no guarantee that it is provided by all
     * web servers and in cases where it is not present, isSecureChannel will
     * fail and throw an EnterpiseSecurityException.
     *
     * @param SafeRequest $request The request object to test.
     *
     * @return bool TRUE if the request was made over Transport Layer Security
     *              FALSE otherwise.
     *
     * @throws EnterpiseSecurityException
     */
    public function isSecureChannel($request)
    {
        if ($request instanceof SafeRequest == false) {
            throw new InvalidArgumentException(
                'isSecureChannel expects an instance of SafeRequest.'
            );
        }

        $isSecure = $request->getServerGlobal('HTTPS');

        if ($isSecure === null) {
            throw new EnterpriseSecurityException(
                'Your Request could not be completed.',
                '$_SERVER[\'HTTPS\'] is not available to isSecureChannel. Cannot determine whether request is secure.'
            );
        }

        if (empty($isSecure) || $isSecure === 'off') {
            return false;
        }

        return true;
    }

    /**
     * @inheritDoc
     */
    public function getParameter($request, $name, $default = null)
    {
        $value = $request->getParameter($name);
        if ($this->validator->isValidInput(
            "HTTP parameter value: " . $value,
            $value,
            "HTTPParameterValue",
            2000,
            true
        )
        ) {
            return $value;
        } else {
            return $default;
        }
    }

    /**
     * Kill all cookies received in the last request from the browser. Note that
     * new cookies set by the application in this response may not be killed by
     * this method.
     *
     * @param SafeRequest $request Request object.
     *
     * @return null.
     */
    public function killAllCookies($request)
    {
        if ($request instanceof SafeRequest == false) {
            throw new InvalidArgumentException(
                'killAllCookies expects an instance of SafeRequest.'
            );
        }
        $cookies = $request->getCookies();
        foreach ($cookies as $name => $_) {
            $this->killCookie($request, $name);
        }
    }

    /**
     * Kills the specified cookie by setting a new cookie that expires
     * immediately. Note that this method does not delete new cookies that are
     * being set by the application for this response.
     *
     * @param SafeRequest $request Request object.
     * @param string      $name    Name of the cookie to be killed.
     *
     * @return null.
     *
     */
    public function killCookie($request, $name)
    {
        if ($request instanceof SafeRequest == false) {
            throw new InvalidArgumentException(
                'killCookie expects an instance of SafeRequest.'
            );
        }
        $value = 'deleted';
        $expire = 1;
        $path = '';
        $domain = '';

        setcookie($name, $value, $expire, $path, $domain);
    }

    /**
     * Takes an HTTP query string and parses it into name-value pairs which are
     * returned as an associative array.  This implementation will ignore
     * duplicate paramater names, returning only the first found parameter.
     *
     * @param string $query The HTTP query string to be parsed.
     *
     * @return array of name value pairs from the query string.
     */
    private function queryToMap($query)
    {
        $map = array();
        $parts = explode('&', $query);

        foreach ($parts as $part) {
            try {
                $nvpair = explode('=', $part);
                $name = ESAPI::getEncoder()->decodeFromURL($nvpair[0]);
                $value = ESAPI::getEncoder()->decodeFromURL($nvpair[1]);
                if (!array_key_exists($name, $map)) {
                    $map[$name] = $value;
                }
            } catch (EncodingException $e) {
                // NoOp - skip this pair - exception was logged already.
            }
        }

        return $map;
    }

    /**
     * Stores the supplied SafeRequest object so that it may be readily accessed
     * throughout ESAPI (and elsewhere).
     *
     * @param SafeRequest $request Current Request object.
     *
     * @return null.
     */
    public function setCurrentHTTP($request)
    {
        if ($request instanceof SafeRequest == false) {
            throw new InvalidArgumentException(
                'setCurrentHTTP expects an instance of SafeRequest.'
            );
        }
        $this->currentRequest = $request;
    }

    /**
     * Retrieves the current SafeRequest.
     *
     * @return SafeRequest the current request.
     */
    public function getCurrentRequest()
    {
        return $this->currentRequest;
    }

    /**
     * Format the Source IP address, URL, URL parameters, and all form parameters
     * into a string suitable for the log file. Be careful not to log sensitive
     * information, and consider masking with the logHTTPRequestObfuscate method.
     *
     * @param SafeRequest $request Current Request object.
     * @param Auditor     $auditor the auditor to write the request to.
     *
     * @return null
     */
    public function logHTTPRequest($request, $auditor)
    {
        $this->logHTTPRequestObfuscate($request, $auditor, null);
    }

    /**
     * Format the Source IP address, URL, URL parameters, and all form parameters
     * into a string suitable for the log file. The list of parameters to obfuscate
     * should be specified in order to prevent sensitive information from being
     * logged. If a null or empty list of parameters is provided, then all
     * parameters will be logged in the clear. If HTTP request logging is done in a
     * central place $paramsToObfuscate could be made a configuration parameter. We
     * include it here in case different parts of the application need to obfuscate
     * different parameters.
     *
     * @param SafeRequest $request           Current Request object.
     * @param Auditor     $auditor           The auditor to write the request to.
     * @param array|null  $paramsToObfuscate The sensitive parameters.
     *
     * @return null
     */
    public function logHTTPRequestObfuscate($request, $auditor, $paramsToObfuscate)
    {
        if ($request instanceof SafeRequest == false) {
            throw new InvalidArgumentException(
                'logHTTPRequestObfuscate expects an instance of SafeRequest.'
            );
        }
        if ($auditor instanceof Auditor == false) {
            throw new InvalidArgumentException(
                'logHTTPRequestObfuscate expects an instance of Auditor.'
            );
        }
        if ($paramsToObfuscate === null) {
            $paramsToObfuscate = array();
        } else {
            if (!is_array($paramsToObfuscate)) {
                throw new InvalidArgumentException(
                    'logHTTPRequestObfuscate expects an array $paramsToObfuscate or null.'
                );
            }
        }

        $msg = '';
        $msg .= $request->getRemoteAddr();
        if ($msg !== '') {
            $msg .= ' ';
        }
        $msg .= $request->getMethod();
        if ($msg !== '') {
            $msg .= ' ';
        }
        $path = $request->getRequestURI() . $request->getPathInfo();
        $msg .= $path;
        $params = $request->getParameterMap();
        if ($path !== '' && sizeof($params, false) > 0) {
            $msg .= '?';
        } else {
            if ($msg !== '') {
                $msg .= ' ';
            }
        }
        $paramBuilder = array();
        foreach ($params as $pName => $pValues) {
            foreach ($pValues as $pval) {
                $pair = '';
                $pair .= "{$pName}";
                if ($pval == '') {
                    $paramBuilder[] = $pair;
                    continue;
                }
                if (in_array($pName, $paramsToObfuscate, true)) {
                    $pair .= '=********';
                } else {
                    $pair .= "={$pval}";
                }
                $paramBuilder[] = $pair;
            }
        }
        $msg .= implode('&', $paramBuilder);

        $cookies = $request->getCookies();
        $sessName = session_name();
        foreach ($cookies as $cName => $cValue) {
            if ($cName !== $sessName) {
                $msg .= "+{$cName}={$cValue}";
            }
        }

        $auditor->info(Auditor::SECURITY, true, $msg);
    }
}

