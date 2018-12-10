<?php
/**
 * Class to authenticate user/pass against a mail server
 *
 * Allow authenticating a user/pass against any mail server running :
 * POP3/POP3S/IMAP/IMAPS/SMTP/SMTPS
 * User: matt
 * Date: 13/09/18
 * Time: 12:21
 *
 * PHP version 5
 *
 * LICENSE: This source file is subject to version 3.01 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_01.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 *
 * @category  ACTweb/<CategoryName>
 * @package   mailAuth
 * @author    Matt Lowe <marl.scot.1@googlemail.com>
 * @copyright 2018 ACTweb
 * @license   http://www.php.net/license/3_01.txt  PHP License 3.01
 * @version   0.5
 * @link      https://actweb.co.uk/php/actweb/mailauth
 */


namespace Actweb;

use Monolog\Handler\NullHandler;
use Monolog\Logger;


/**
 *
 * Short description for file
 *
 * Long description for file (if any)...
 * Class MailAuth
 * User: matt
 * Date: 13/09/18
 * Time: 12:31
 *
 * @category  ACTweb/<CategoryName>
 * @package   mailAuth
 * @author    Matt Lowe <marl.scot.1@googlemail.com>
 * @copyright 2018 ACTweb
 * @license   http://www.php.net/license/3_01.txt  PHP License 3.01
 * @version   0.0.1
 * @link      https://actweb.co.uk/php/actweb/mailauth
 */
class MailAuth
{
    /**
     * @var string URL of mail server to authenticate against
     */
    private $mailServerUrl;
    /**
     * @var int Port to connect to on mail server
     */
    private $serverPort;
    /**
     * @var string Server Type (POP3/POP3S/IMAP/IMAPS/SMTP/SMTPS)
     */
    private $serverType;
    /**
     * @var array of valid server types and the ports that they use
     */
    private $serverTypes
        = array(
            'POP3' => array(
                'port' => 110
            ),
            'POP3S' => array(
                'port' => 995
            ),
            'IMAP' => array(
                'port' => 143
            ),
            'IMAPS' => array(
                'port' => 993
            ),
            'SMTP' => array(
                'port' => 25
            ),
            'SMTPS' => array(
                'port' => 465
            )
        );
    /**
     * @var array Of error codes, descriptions and help text
     */
    private $errors
        = array(
            '1' => array(
                'desc' => 'Port number out of range',
                'help' => 'Please ensure that the port number is set between 1 & 65535'
            ),
            '2' => array(
                'desc' => 'Invalid Server Type',
                'help' => 'Valid server types are POP3 / POP3S / IMAP / IMAPS / SMTP / SMTPS'
            ),
            '3' => array(
                'desc' => 'Invalid Password Type',
                'help' => 'Valid password types are : plain'
            ),
            '4' => array(
                'desc' => 'Server type has no authentication methods',
                'help' => 'Someone screwed up big time!, authentication method doesn\'t exist'
            )
        );
    /**
     * @var string Username to authenticate
     */
    private $username;
    /**
     * @var string Password to authenticate
     */
    private $password;
    /**
     * @var string Type of password used (plain/md5hash etc)
     */
    private $passwordType = 'plain';
    /**
     * Only plain passwords are support at the moment.
     *
     * @var array List of password types and the method to call to implement
     */
    private $passwordTypes
        = array(
            'plain' => 'authPlain',
        );
    /**
     * @var \Monolog\Logger
     */
    private $logger;
    /**
     * @var bool If false and we are authenticating via SSL, then ignore certificate errors
     */
    private $sslCheck = true;
    /**
     * @var bool True if we passed authentication, false if we failed
     */
    private $authenticated;

    /**
     * @var int Connection Timeout, only used on SMTP at the moment.
     */
    private $timeOut = 30;
    /**
     * @var string Type of new line to use for SMTP communication
     */
    private $newLine = "\r\n";

    /**
     * @var string Local Hostname for SMTP communication
     */
    private $smtpLocalHost;
    /**
     * Basic Constructor
     *
     * @param $log \Monolog\Logger | null
     */
    public function __construct($log = null)
    {
        //$this->logger = new Logger('mailAuth');
        if ($log === null) {
            $this->logger->pushHandler(new NullHandler());
        } else {
            $this->logger = $log;
        }
    }

    /**
     * Checks if we are checking for valid SSL certificates
     * and if we are not, then return correct string to append to command
     *
     * @return string
     */
    private function sslValidate()
    {
        if ($this->sslCheck) {
            return '';
        }
            return '/novalidate-cert';
    }

    /**
     * Public method that calls the respective auth method within the class
     *
     * @return bool
     * @throws \ErrorException If method auth$serverType doesn't exist
     */
    public function authenticate()
    {
        $method = 'auth' . $this->serverType;
        $this->debug('Authenticate called for method', $method);
        if (is_callable($method, true)) {
            $return = $this->$method();
        } else {
            $this->throwError(4);
        }
        /** @noinspection PhpUndefinedVariableInspection */
        $this->debug(
            'Authentication request type :' . $method . ' returned ', $return
        );
        return $return;
    }

    /**
     * Configure server string for POP3
     *
     * @return bool
     */
    private function authPOP3()
    {
        /*
         * SSL Validate has to be included as IMAP_OPEN checks
         * certificate even if not using POP3S/IMAPS!
         */
        $command = '/pop3' . $this->sslValidate();
        return $this->imap($command);
    }

    /**
     * Configure server string for POP3S
     *
     * @return bool
     */
    private function authPOP3S()
    {
        $command = '/pop3/ssl' . $this->sslValidate();
        return $this->imap($command);
    }

    /**
     * Configure server string for IMAP
     *
     * @return bool
     */
    private function authIMAP()
    {
        /*
        * SSL Validate has to be included as IMAP_OPEN checks
        * certificate even if not using POP3S/IMAPS!
        */
        $command = '/imap' . $this->sslValidate();
        return $this->imap($command);
    }

    /**
     * Configure server string for IMAPS
     *
     * @return bool
     */
    private function authIMAPS()
    {
        $command = '/imap/ssl' . $this->sslValidate();
        return $this->imap($command);
    }

    /**
     * Build the connection string (command) to connect to the server
     * attempt to connect to server, if successful, close stream and set
     * authenticated to true, else set authenticated to false.
     *
     * @param string $type Command string to be added to end of server URL & PORT
     *
     * @return bool True if login was successful otherwise false
     */
    private function imap($type)
    {
        $command = '{' .
            $this->mailServerUrl .
            ':' .
            $this->serverPort .
            $type .
            '}';
        $this->debug('Attempting IMAP connect', $command);
        // Added 0 retries to avoid getting banned for invalid user/pass
        set_error_handler(array($this, 'errorHandler'));
        $imap = \imap_open($command, $this->username, $this->password, 0, 0);
        restore_error_handler();
        if (false !== $imap) {
            imap_close($imap);
            $this->authenticated = true;
        } else {
            $this->authenticated = false;
        }
        $this->debug('IMAP Connect Error Dump', imap_errors());
        return $this->authenticated;
    }


    /**
     * Configure server string for SMTP
     *
     * @return bool|null
     */
    private function authSMTP()
    {
        $command = '';
        return $this->smtp($command);
    }

    /**
     * Configure server string for SMTPS
     *
     * @return bool|null
     */
    private function authSMTPS()
    {
        $command = 'ssl://';
        return $this->smtp($command);
    }

    /**
     * Check SMTP authentication by trying to log into the SMTP server
     * and checking if result code '235 Authenticated' is returned
     * Adapted from :
     * http://support.webecs.com/kb/a390/php-mail-script-with-smtp-authentication.aspx#
     * Hav left full debugging output in the SMTP communication block, to allow
     * easier bug fixes!
     *
     * @param string $type Additional string to prepend to server URL
     *
     * @return bool|null True/False returned on Auth/NotAuth and NULL on server failure
     */
    private function smtp($type)
    {
        $newLine = $this->newLine;
        $smtpServer = $type . $this->mailServerUrl;
        $this->debug('SMTP Auth called', $smtpServer);
        $smtpConnect = fsockopen(
            $smtpServer,
            $this->serverPort,
            $errorCode,
            $errorString,
            $this->timeOut
        );
        $this->debug('SMTP Socket Open Result', $smtpConnect);
        set_error_handler(array($this, 'errorHandler'));
        $smtpResponse = (!empty($smtpConnect) ? fgets($smtpConnect, 515)
            : false);
        restore_error_handler();
        $this->debug('Connect to SMTP ', $smtpResponse);
        if (empty($smtpConnect)) {
            $this->smtpError = array(
                'errorno' => $errorCode,
                'error' => $errorString
            );
            return null;
        }
        $this->debug('SMTP CHAT : ', 'HELO '.$this->smtpLocalHost);
        //
        fputs($smtpConnect, 'HELO ' . $this->smtpLocalHost . $newLine);
        $smtpResponse = fgets($smtpConnect, 515);
        $this->debug('SMTP HELO ' . $this->mailServerUrl, $smtpResponse);
        //
        $this->debug('SMTP CHAT : ', 'AUTH LOGIN');
        fputs($smtpConnect, 'AUTH LOGIN' . $newLine);
        $smtpResponse = fgets($smtpConnect, 515);
        $this->debug('SMTP Auth request', $smtpResponse);
        //
        $this->debug('SMTP CHAT : ', base64_encode($this->username . $newLine));
        fputs($smtpConnect, base64_encode($this->username). $newLine);
        $smtpResponse = fgets($smtpConnect, 515);
        $this->debug('SMTP Auth username', $smtpResponse);
        //
        $this->debug('SMTP CHAT : ', base64_encode($this->password). $newLine);
        fputs($smtpConnect, base64_encode($this->password). $newLine);
        $smtpResponse = fgets($smtpConnect, 515);
        $this->debug('SMTP Auth password', $smtpResponse);
        $authResult=$smtpResponse;
        fputs($smtpConnect, 'QUIT' . $newLine);
        $smtpResponse = fgets($smtpConnect, 515);
        $this->debug('SMTP QUIT', $smtpResponse);
        $authResult=substr($authResult, 0, 3);
        $this->debug('SMTP Authentication Result', $authResult);
        return ($authResult === '235');
    }


    /*
     * =========================================================================
     * SET & GET Methods
     * =========================================================================
     */


    /**
     * @return string
     */
    public function getMailServerUrl()
    {
        return $this->mailServerUrl;
    }

    /**
     * @todo Add URL validation before setting
     *
     * @param string $mailServerUrl
     *
     * @return MailAuth
     */
    public function setMailServerUrl($mailServerUrl)
    {
        $this->debug('MailServerUrl set to', $mailServerUrl);
        $this->mailServerUrl = $mailServerUrl;
        return $this;
    }

    /**
     * @return int
     */
    public function getServerPort()
    {
        return $this->serverPort;
    }

    /**
     * Can accept any int from 1-65535
     *
     * @param int $serverPort
     *
     * @return MailAuth
     * @throws \ErrorException If invalid port number is supplied
     */
    public function setServerPort($serverPort)
    {
        $this->debug('ServerPort set to', $serverPort);
        if (($serverPort < 1) || ($serverPort > 65535)) {
            $this->throwError(1);
        }
        $this->serverPort = $serverPort;
        return $this;
    }

    /**
     * @return string
     */
    public function getServerType()
    {
        return $this->serverType;
    }

    /**
     * Sets the server type we will authenticate to
     * This is checked against our list of supported types
     * before setting
     * If $serverPort is not set yet, then set to correct port.
     *
     * @param string $serverType
     *
     * @return MailAuth
     * @throws \ErrorException If an invalid Server Type is passed
     */
    public function setServerType($serverType)
    {
        $this->debug('ServerType set to', $serverType);
        $serverType = strtoupper($serverType);
        if (array_key_exists($serverType, $this->serverTypes)) {
            $this->serverType = $serverType;
        } else {
            $this->throwError(2);
        }
        if ($this->serverPort === null) {
            $this->serverPort = $this->serverTypes[$serverType]['port'];
        }
        return $this;
    }

    /**
     * @return \Monolog\Logger
     */
    public function getLogger()
    {
        return $this->logger;
    }

    /**
     * @param \Monolog\Logger $logger
     *
     * @return MailAuth
     */
    public function setLogger($logger)
    {
        $this->debug('Logger set to', $logger);
        $this->logger = $logger;
        return $this;
    }

    /**
     * @return array
     */
    public function getServerTypes()
    {
        return $this->serverTypes;
    }

    /**
     * @return array
     */
    public function getErrors()
    {
        return $this->errors;
    }

    /**
     * Merges the supplied list of error messages and help
     * into our error array, could be used for translations etc.
     *
     * @param array $errors
     *
     * @return MailAuth
     */
    public function setErrors($errors)
    {
        $this->debug('Error List set to', $errors);
        $errorsTmp = array_replace_recursive($this->errors, $errors);
        $this->errors = $errorsTmp;
        return $this;
    }

    /**
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @param string $username
     *
     * @return MailAuth
     */
    public function setUsername($username)
    {
        $this->debug('Username set to', $username);
        $this->username = $username;
        return $this;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @param string $password
     *
     * @return MailAuth
     */
    public function setPassword($password)
    {
        $this->debug('Password set to', $password);
        $this->password = $password;
        return $this;
    }

    /**
     * @return string
     */
    public function getPasswordType()
    {
        return $this->passwordType;
    }

    /**
     * Sets password type, after checking that the passed type
     * is in our list of valid passwordTypes
     *
     * @param string $passwordType
     *
     * @return MailAuth
     * @throws \ErrorException If password type is not defined in $passwordTypes
     */
    public function setPasswordType($passwordType)
    {
        $this->debug('Password type set to', $passwordType);
        if (array_key_exists($passwordType, $this->passwordTypes)) {
            $this->passwordType = $passwordType;
        } else {
            $this->throwError(3);
        }
        return $this;
    }

    /**
     * @return array
     */
    public function getPasswordTypes()
    {
        return $this->passwordTypes;
    }

    /**
     * @return bool
     */
    public function isSslCheck()
    {
        return $this->sslCheck;
    }

    /**
     * @param bool $sslCheck
     *
     * @return MailAuth
     */
    public function setSslCheck($sslCheck)
    {
        $this->sslCheck = $sslCheck;
        return $this;
    }

    /**
     * @return int
     */
    public function getTimeOut()
    {
        return $this->timeOut;
    }

    /**
     * @param int $timeOut
     */
    public function setTimeOut($timeOut)
    {
        $this->timeOut = $timeOut;
    }

    /**
     * @return bool
     */
    public function isAuthenticated()
    {
        return $this->authenticated;
    }

    /**
     * @return string
     */
    public function getNewLine()
    {
        return $this->newLine;
    }

    /**
     * @param string $newLine
     *
     * @return MailAuth
     */
    public function setNewLine($newLine)
    {
        $this->newLine = $newLine;
        return $this;
    }

    /**
     * @return string
     */
    public function getSmtpLocalHost()
    {
        return $this->smtpLocalHost;
    }

    /**
     * @param string $smtpLocalHost
     *
     * @return MailAuth
     */
    public function setSmtpLocalHost($smtpLocalHost)
    {
        $this->smtpLocalHost = $smtpLocalHost;
        return $this;
    }

    /*
     * =========================================================================
     * DEBUG / LOGGING Methods
     * =========================================================================
     */

    /**
     * Throws any exception errors
     * used instead of individual throws to allow putting all errors
     * and descriptions into an array, making it easier to alter error
     * descriptions. Eg. to change language
     * @todo Add traceback call to allow more detailed information to be passed back
     *
     * @param int $errorNo Error number to throw
     *
     * @throws \ErrorException
     */
    private function throwError($errorNo)
    {
        $this->debug('Exception thrown!', $this->errors[$errorNo], 'error');
        if (isset($this->errors[$errorNo])) {
            throw new \ErrorException(
                $this->errors[$errorNo]['desc'], $errorNo
            );
        }
        throw new \ErrorException(
            'Something bad has happened Error code :' . $errorNo
            . ': is invalid', 255
        );
    }

    /**
     * @param string       $desc  Debug description
     * @param string|array $data  String/Array of data to include in debug
     * @param string       $level Debug error level debug/error/info etc
     */
    private function debug($desc, $data = '', $level = 'debug')
    {
        // Convert $data to array if its a string as Monolog complains about strings!
        if (!is_array($data)) {
            $data = array($data);
        }
        $this->logger->$level($desc, $data);
    }

    /**
     * Error handler, used to prevent PHP displaying warnings
     * if they are turned on.
     * Just gets the data and passes it to the debug method
     *
     * @param int    $errno   Error Number to display
     * @param string $errstr  Error String to display
     * @param string $errfile Filename error occurred in
     * @param int    $errline Line number error occurred at
     */
    private function errorHandler($errno, $errstr, $errfile, $errline)
    {
        $data = array(
            'Error Number' => $errno,
            'Error String' => $errstr,
            'Error File  ' => $errfile,
            'Error Line  ' => $errline
        );
        $this->debug('PHP Emitted an error', $data, 'error');
    }

}
