<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2011 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author  Bipin Upadhyay <http://projectbee.org/blog/contact/>
 * @created 2009
 * @since   1.4
 * @version 1.07
 * @package ESAPI_Reference
 */

//TODO: Cleanup to be done, as suggested by Mike

require_once dirname(__FILE__) . '/../User.php';
define("MAX_ROLE_LENGTH", 250);

/**
 * Reference Implementation of the DefaultUser interface.
 *
 * @category  OWASP
 * @package   ESAPI_Reference
 * @author    Bipin Upadhyay <http://projectbee.org/blog/contact/>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class DefaultUser implements User
{
    //Configs
    public $allowedLoginAttempts = 3;
    public $sessionTimeout = 3600; #one hour
    public $sessionAbsoluteTimeout = 7200; #2 hours
    //TODO: load these from config
    private $username = null;
    private $password = null;
    private $uid = null;
    private $userInfo = array();
    private $pathToUsersFiles = "../../test/testresources/users.txt";


    private static $IDLE_TIMEOUT_LENGTH = null;
    private static $ABSOLUTE_TIMEOUT_LENGTH = null;

    /** This user's account id. */
    private $accountId = 0;

    /** This user's account name. */
    private $accountName = "";

    /** This user's screen name (account name alias). */
    private $screenName = "";

    /** This user's CSRF token. */
    private $csrfToken = "";

    /** This user's assigned roles. */
    private $roles = array();

    /** Whether this user's account is locked. */
    private $locked = false;

    /** Whether this user is logged in. */
    private $loggedIn = true;

    /** Whether this user's account is enabled. */
    private $enabled = false;

    /** The last host address used by this user. */
    private $lastHostAddress = null;

    /** The session's this user is associated with */
    private $sessions = array();

    /** The failed login count for this user's account. */
    private $failedLoginCount = 0;

    const MAX_ROLE_LENGTH = 250;


    public function __construct($accountName)
    {
        $this->setAccountName($accountName);

        //TODO: Not the best way IMHO. I'd rather call the method via factory object each time. Needs discussion..
        $this->IDLE_TIMEOUT_LENGTH = ESAPI::getSecurityConfiguration()->getSessionIdleTimeoutLength();
        $this->ABSOLUTE_TIMEOUT_LENGTH = ESAPI::getSecurityConfiguration()->getSessionAbsoluteTimeoutLength();

        do {
            $id = ESAPI::getRandomizer()->getRandomLong();
            if (ESAPI::getAuthenticator()->getUserById($id) == null && $id != 0) {
                $this->setAccountID($id);
            }
        } while ($this->getAccountID() == 0);
    }

    public function __destruct()
    {
        $this->writeUserInfo();
    }

    /**
     * This is intended to compute the password hash for a password
     *
     * @param String $Password
     *
     * @return String the hash
     */
    public function hashPassword($Password)
    {
        //TODO: code this
        return "";
    }

    /**
     * This array holds the keys for users fields in order and is used in parseUserInfo()
     *
     * @var Array
     */
    private $userInfoFields
        = array(
            "accountName", "hashedPassword", "roles", "locked", "enabled", "rememberToken", "csrfToken",
            "oldPasswordHashes", "lastPasswordChangeTime", "lastLoginTime", "lastFailedLoginTime", "expirationTime",
            "failedLoginCount"
        );

    private function setUserInfo($Field, $Value)
    {
        $this->userInfo[$Field] = $Value;
    }

    private function getUserInfo($Field)
    {
        if (!array_key_exists($Field, $this->userInfo)) {
            return null;
        }
        return $this->userInfo[$Field];
    }

    private function parseUserInfo($Data)
    {
        $Data = explode(" | ", $Data);
        $n = 0;
        $this->userInfo = array();
        foreach ($Data as $D) {
            $this->userInfo[$this->_userInfoFields[$n++]] = $D;
        }
    }

    private function readUserInfo()
    {
        $Compare = $this->username;
        $fp = fopen(dirname(__FILE__) . "/" . $this->pathToUsersFiles, "r");
        if (!$fp) {
            throw new Exception("Can not open the users.txt file!");
        }
        while (!feof($fp)) {
            $Line = fgets($fp);
            if (substr($Line, 0, strlen($Compare)) == $Compare) {
                $Data = $Line;
                $this->parseUserInfo($Data);
                break;
            }
        }
        fclose($fp);
    }

    private function writeUserInfo()
    {
        $Compare = $this->username;
        $fp = fopen(dirname(__FILE__) . "/" . $this->pathToUsersFiles, "r");
        if (!$fp) {
            throw new Exception("Can not open the users.txt file!");
        }
        $Data = "";
        while (!feof($fp)) {
            $Line = fgets($fp);
            $Line = trim($Line);
            if (strlen($Line) > strlen($Compare) and substr($Line, 0, strlen($Compare)) != $Compare) {
                $Data .= $Line . "\n";
            }
        }
        fclose($fp);
        $fp = fopen(dirname(__FILE__) . "/" . $this->pathToUsersFiles, "w+");
        if (!$fp) {
            throw new Exception("Can not open the users.txt file for writing!!");
        }
        fwrite($fp, $Data);
        if ($this->userInfo) {
            fwrite($fp, implode(" | ", $this->userInfo));
        }
        fclose($fp);
    }

    /**
     * Gets this user's account name.
     *
     * @return the account name
     */
    public function getAccountName()
    {
        //TODO: Redo
        return $this->accountName;
    }

    /**
     * Adds a role to this user's account.
     *
     * @param role
     *         the role to add
     *
     * @throws AuthenticationException
     *         the authentication exception
     */
    public function addRole($role)
    {
        $roleName = strtolower($role);
        if (false /*ESAPI::getValidator()->isValidInput("addRole", $roleName, "RoleName", MAX_ROLE_LENGTH, false) */) {
            //TODO: Verify if this is correct
            $this->roles[] = $roleName;
            ESAPI::getLogger("DefaultUser")->info(
                ESAPILogger::SECURITY,
                false,
                "Role " . $roleName . " added to " . $this->getAccountName()
            );
        } else {
            //TODO: Not done in Java, but shouldn't this be logged as well?
            throw new AuthenticationAccountsException(
                "Add role failed",
                "Attempt to add invalid role " . $roleName . " to " . $this->getAccountName()
            );
        }
    }

    /**
     * Adds a set of roles to this user's account.
     *
     * @param Array $newRoles
     *         the new roles to add
     *
     * @throws AuthenticationException
     *         the authentication exception
     */
    public function addRoles($newRoles)
    {
        foreach ($newRoles as $role) {
            $this->addRole($role);
        }
    }

    /**
     * Sets the user's password, performing a verification of the user's old password, the equality of the two new
     * passwords, and the strength of the new password.
     *
     * @param oldPassword
     *         the old password
     * @param newPassword1
     *         the new password
     * @param newPassword2
     *         the new password - used to verify that the new password was typed correctly
     *
     * @throws AuthenticationException
     *         if newPassword1 does not match newPassword2, if oldPassword does not match the stored old password, or if the new password does not meet complexity requirements
     * @throws EncryptionException
     */
    public function changePassword($oldPassword, $newPassword1, $newPassword2)
    {
        ESAPI::getAuthenticator()->changePassword($this, $oldPassword, $newPassword1, $newPassword2);
    }

    /**
     * Disable this user's account.
     */
    public function disable()
    {
        $this->enabled = false;
        ESAPI::getLogger("DefaultUser")->info(
            ESAPILogger::SECURITY,
            true,
            "Account disabled: " . $this->getAccountName()
        );
    }

    /**
     * Enable this user's account.
     */
    public function enable()
    {
        $this->enable = true;
        ESAPI::getLogger("DefaultUser")->info(
            ESAPILogger::SECURITY,
            true,
            "Account enabled: " . $this->getAccountName()
        );
    }

    /**
     * Gets this user's account id number.
     *
     * @return Integer the account id
     */
    public function getAccountId()
    {
        return $this->accountId;
    }

    /**
     * Gets the CSRF token for this user's current sessions.
     *
     * @return String the CSRF token
     */
    public function getCSRFToken()
    {
        return $this->csrfToken;
    }

    /**
     * Returns the date that this user's account will expire.
     *
     * @return Date representing the account expiration time.
     */
    public function getExpirationTime()
    {
        //TODO: Redo
        return $this->getUserInfo("expirationTime");
    }

    /**
     * Returns the number of failed login attempts since the last successful login for an account. This method is
     * intended to be used as a part of the account lockout feature, to help protect against brute force attacks.
     * However, the implementor should be aware that lockouts can be used to prevent access to an application by a
     * legitimate user, and should consider the risk of denial of service.
     *
     * @return Integer the number of failed login attempts since the last successful login
     */
    public function getFailedLoginCount()
    {
        return $this->failedLoginCount;
    }

    /**
     * Returns the last host address used by the user. This will be used in any log messages generated by the processing
     * of this request.
     *
     * @return String the last host address used by the user
     */
    public function getLastHostAddress()
    {
        if ($this->lastHostAddress == null) {
            return "local";
        } else {
            return $this->lastHostAddress;
        }
    }

    /**
     * Returns the date of the last failed login time for a user. This date should be used in a message to users after a
     * successful login, to notify them of potential attack activity on their account.
     *
     * @return date of the last failed login
     *
     * @throws AuthenticationException
     *         the authentication exception
     */
    public function getLastFailedLoginTime()
    {
        //TODO: Redo
        return $this->getUserInfo("lastFailedLoginTime");
    }

    /**
     * Returns the date of the last successful login time for a user. This date should be used in a message to users
     * after a successful login, to notify them of potential attack activity on their account.
     *
     * @return date of the last successful login
     */
    public function getLastLoginTime()
    {
        //TODO: Redo
        return $this->getUserInfo("lastLoginTime");
    }

    /**
     * Gets the date of user's last password change.
     *
     * @return the date of last password change
     */
    public function getLastPasswordChangeTime()
    {
        //TODO: Redo
        return $this->getUserInfo("lastPasswordChangeTime");
    }

    /**
     * Gets the roles assigned to a particular account.
     *
     * @return Array an immutable set of roles
     */
    public function getRoles()
    {
        //TODO: Redo
        return explode(",", $this->getUserInfo("roles"));
    }

    /**
     * Gets the screen name (alias) for the current user.
     *
     * @return String the screen name
     */
    public function getScreenName()
    {
        return $this->screenName;
        //return $this->getUserInfo("accountName");
    }

    /**
     * Adds a session for this User.
     *
     * @param $HttpSession string sessionID
     */
    public function addSession($HttpSession = null)
    {
        //TODO: Redo
        //TODO: no session established, throw some errors
        if (session_id() == "")
        {
            ;
        }
        if ($HttpSession === null) {
            $HttpSession = session_id();
        }
        $_SESSION[$this->getAccountId()][$HttpSession] = array("start" => time(), "lastUpdate" => time());
    }

    /**
     * Removes a session for this User.
     *
     * @param $HttpSession string session id
     */
    public function removeSession($HttpSession = null)
    {
        //TODO: Redo
        if ($HttpSession === null) {
            $HttpSession = session_id();
        }
        unset($_SESSION[$this->getAccountId()][$HttpSession]);
    }

    /**
     * Returns the list of sessions associated with this User.
     *
     * @return Array sessions
     */
    public function getSessions()
    {
        //TODO: Redo
        return $_SESSION[$this->getAccountId()];
    }

    /**
     * Increment failed login count.
     */
    public function incrementFailedLoginCount()
    {
        $this->failedLoginCount++;
    }

    public function setFailedLoginCount($count)
    {
        //TODO: Redo
        $this->setUserInfo("failedLoginCount", $count);
        if ($this->getFailedLoginCount() >= $this->allowedLoginAttempts) {
            $this->lock();
        }
    }

    /**
     * Checks if user is anonymous.
     *
     * @return true, if user is anonymous
     */
    public function isAnonymous()
    {
        //TODO: Redo
        //Need to discuss the concept of anonymous in context with PHP
        if ($this->uid === null) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Checks if this user's account is currently enabled.
     *
     * @return true, if account is enabled
     */
    public function isEnabled()
    {
        return $this->enabled;
    }

    /**
     * Checks if this user's account is expired.
     *
     * @return true, if account is expired
     */
    public function isExpired()
    {
        //TODO: Redo
        $ExpTime = $this->getUserInfo("expirationTime");
        if ($ExpTime < time()) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Checks if this user's account is assigned a particular role.
     *
     * @param String $role the role for which to check
     *
     * @return true, if role has been assigned to user
     */
    public function isInRole($role)
    {
        return in_array(strtolower($role), $this->roles);
    }

    /**
     * Checks if this user's account is locked.
     *
     * @return true, if account is locked
     */
    public function isLocked()
    {
        return $this->locked;
    }

    /**
     * Tests to see if the user is currently logged in.
     *
     * @return true, if the user is logged in
     */
    public function isLoggedIn()
    {
        return $this->loggedIn;
    }

    /**
     * Tests to see if this user's session has exceeded the absolute time out based
     * on ESAPI's configuration settings.
     *
     * @param String $HttpSession optional session id
     *
     * @return true, if user's session has exceeded the absolute time out
     */
    public function isSessionAbsoluteTimeout($HttpSession = null)
    {
        //TODO: Redo
        if ($HttpSession === null) {
            $HttpSession = session_id();
        }
        if (isset($_SESSION[$this->getAccountId()][$HttpSession]['start'])) {
            return (time() - $_SESSION[$this->getAccountId()][$HttpSession]['start']) > $this->sessionAbsoluteTimeout;
        }
        return true;
    }

    /**
     * Tests to see if the user's session has timed out from inactivity based
     * on ESAPI's configuration settings.
     *
     * A session may timeout prior to ESAPI's configuration setting due to
     * the servlet container setting for session-timeout in web.xml. The
     * following is an example of a web.xml session-timeout set for one hour.
     *
     * <session-config>
     *   <session-timeout>60</session-timeout>
     * </session-config>
     *
     * @param String $HttpSession optional session id
     *
     * @return true, if user's session has timed out from inactivity based
     *               on ESAPI configuration
     */
    public function isSessionTimeout($HttpSession = null)
    {
        //TODO: Redo
        if ($HttpSession === null) {
            $HttpSession = session_id();
        }
        #XXX: You should add some logic to update session time somewhere!
        if (isset($_SESSION[$this->getAccountId()][$HttpSession]['lastUpdate'])) {
            return (time() - $_SESSION[$this->getAccountId()][$HttpSession]['lastUpdate']) > $this->sessionTimeout;
        }
        return true;
    }

    /**
     * Lock this user's account.
     */
    public function lock()
    {
        $this->locked = true;
        ESAPI::getLogger("DefaultUser")->info(
            ESAPILogger::SECURITY,
            true,
            "Account locked: " . $this->getAccountName()
        );
    }

    /**
     * Login with password.
     *
     * @param String $password the password
     *
     * @throws AuthenticationException
     *         if login fails
     */
    public function loginWithPassword($password)
    {
        //TODO: time() might not be the correct format to be used?
        if (is_null($password) || $password == "") {
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException("Login failed", "Missing password: " . $this->getAccountName());
        }

        // don't let disabled users log in
        if (!$this->isEnabled()) {
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException(
                "Login failed",
                "Disabled user attempt to login: " . $this->getAccountName()
            );
        }

        // don't let locked users log in
        if ($this->isLocked()) {
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException(
                "Login failed",
                "Locked user attempt to login: " . $this->getAccountName()
            );
        }

        // don't let expired users log in
        if ($this->isExpired()) {
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException(
                "Login failed",
                "Expired user attempt to login: " . $this->getAccountName()
            );
        }

        $this->logout();

        if ($this->verifyPassword($password)) {
            $this->loggedIn = true;
            ESAPI::getHttpUtilities()->changeSessionIdentifier(ESAPI::currentRequest());
            ESAPI::getAuthenticator()->setCurrentUser($this);
            $this->setLastLoginTime(time());
            $this->setLastHostAddress(ESAPI::getHttpUtilities()->getCurrentRequest()->getRemoteHost());
            ESAPI::getLogger("DefaultUser")->trace(ESAPILogger::SECURITY, "User logged in: " . $this->accountName);
        } else {
            $this->loggedIn = false;
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException(
                "Login failed",
                "Incorrect password provided for " . $this->getAccountName()
            );
        }
    }

    /**
     * Logout this user.
     */
    public function logout()
    {
        //TODO: Redo
        //TODO: ESAPI.httpUtilities().killCookie( ESAPI.currentRequest(), ESAPI.currentResponse(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME );
        if (isset($_SESSION[$this->getAccountId()])) {
            unset($_SESSION[$this->getAccountId()]);
        }
        //TODO: ESAPI.httpUtilities().killCookie(ESAPI.currentRequest(), ESAPI.currentResponse(), "PHPSESSIONID");
        $this->loggedIn = false;
    }

    /**
     * Removes a role from this user's account.
     *
     * @param String $role the role to remove
     *
     * @throws AuthenticationException
     *         the authentication exception
     */
    public function removeRole($role)
    {
        $role = strtolower($role);
        unset($this->roles[$role]);
        ESAPI::getLogger("DefaultLogger")->trace(
            ESAPILogger::SECURITY,
            true,
            "Role " . $role . " removed from " . $this->getAccountName()
        );
    }

    /**
     * Returns a token to be used as a prevention against CSRF attacks. This token should be added to all links and
     * forms. The application should verify that all requests contain the token, or they may have been generated by a
     * CSRF attack. It is generally best to perform the check in a centralized location, either a filter or controller.
     * See the verifyCSRFToken method.
     *
     * @return the new CSRF token
     *
     * @throws AuthenticationException
     *         the authentication exception
     */
    public function resetCSRFToken()
    {
        //TODO: Uncomment when Encoder's implemented
        //        $this->csrfToken = ESAPI::getRandomizer()->getRandomString(8, DefaultEncoder::CHAR_ALPHANUMERICS);
        return $csrfToken;
    }

    /**
     * Sets this user's account name.
     *
     * @param String $accountName the new account name
     */
    public function setAccountName($accountName)
    {
        $oldAccountName = $this->getAccountName();
        $this->accountName = strtolower($accountName);
        if (!is_null($oldAccountName)) {
            ESAPI::getLogger("DefaultUser")->info(
                ESAPILogger::SECURITY,
                true,
                "Account name changed from " . $oldAccountName . " to " . $this->getAccountName()
            );
        }
    }

    /**
     * Sets this user's account ID
     *
     * @param integer $accountId
     *
     * @return unknown_type
     */
    public function setAccountID($accountId)
    {
        $this->accountId = $accountId;
    }

    /**
     * Sets the date and time when this user's account will expire.
     *
     * @param $ExpirationTime Timestamp the new expiration time
     */
    public function setExpirationTime($ExpirationTime)
    {
        //TODO: Redo
        $this->setUserInfo("expirationTime", $ExpirationTime);
    }

    /**
     * Sets the roles for this account.
     *
     * @param Array $Roles the new roles
     *
     * @throws AuthenticationException
     *         the authentication exception
     */
    public function setRoles($Roles)
    {
        //TODO: Redo
        $this->setUserInfo("roles", implode(",", $Roles));
    }

    /**
     * Sets the screen name (username alias) for this user.
     *
     * @param String $screenName the new screen name
     */
    public function setScreenName($screenName)
    {
        $this->screenName = $screenName;
        ESAPI::getLogger("DefaultUser")->info(
            ESAPILogger::SECURITY,
            true,
            "ScreenName changed to " . $screenName . " for " . $this->getAccountName()
        );
    }

    /**
     * Unlock this user's account.
     */
    public function unlock()
    {
        $this->locked = false;
        $this->failedLoginCount = 0;
        ESAPI::getLogger("DefaultUser")->info(
            ESAPILogger::SECURITY,
            true,
            "Account unlocked: " . $this->getAccountName()
        );
    }

    /**
     * Verify that the supplied password matches the password for this user. This method
     * is typically used for "reauthentication" for the most sensitive functions, such
     * as transactions, changing email address, and changing other account information.
     *
     * @param $password the password that the user entered
     *
     * @return true, if the password passed in matches the account's password
     *
     * @throws EncryptionException
     */
    public function verifyPassword($password)
    {
        return ESAPI::getAuthenticator()->verifyPassword($this, $password);
    }

    /**
     * Set the time of the last failed login for this user.
     *
     * @param Integer $LastFailedLoginTime Timestamp the date and time when the user just failed to login correctly.
     */
    public function setLastFailedLoginTime($LastFailedLoginTime)
    {
        //TODO: Redo
        $this->setUserInfo("lastFailedLoginTime", $LastFailedLoginTime);
    }

    /**
     * Set the last remote host address used by this user.
     *
     * @param $remoteHost The address of the user's current source host.
     */
    public function setLastHostAddress($RemoteHost)
    {
        //TODO: Redo
        if ($this->lastHostAddress != null && $this->lastHostAddress != $RemoteHost) {
            // returning remote address not remote hostname to prevent DNS lookup
            new AuthenticationHostException(
                "Host change",
                "User session just jumped from " . $this->lastHostAddress . " to " . $RemoteHost
            );
        }
        $this->lastHostAddress = $RemoteHost;
    }

    /**
     * Set the time of the last successful login for this user.
     *
     * @param Integer $LastLoginTime Timestamp the date and time when the user just successfully logged in.
     */
    public function setLastLoginTime($LastLoginTime)
    {
        //TODO: Redo
        $this->setUserInfo("lastLoginTime", $LastLoginTime);
    }

    /**
     * Set the time of the last password change for this user.
     *
     * @param Integer $LastPasswordChangeTime Timestamp the date and time when the user just successfully changed his/her password.
     */
    public function setLastPasswordChangeTime($LastPasswordChangeTime)
    {
        //TODO: Redo
        $this->setUserInfo("lastPasswordChangeTime", $LastPasswordChangeTime);
    }

    /**
     * The ANONYMOUS user is used to represent an unidentified user. Since there is
     * always a real user, the ANONYMOUS user is better than using null to represent
     * this.
     */
    //FIXME:
    public $ANONYMOUS = null;
}