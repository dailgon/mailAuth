<?php
/**
 * Example code for authentication
 *
 * Long description for file (if any)...
 * User: matt
 * Date: 13/09/18
 * Time: 16:01
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
 * @version   0.0.1
 * @link      http://www.actweb.info/package/mailAuth
 */

namespace Actweb;

include_once __DIR__.'/../vendor/autoload.php';
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger=new Logger('auth');
$logger->pushHandler(new StreamHandler(__DIR__.'/auth.log', LOGGER::DEBUG));
$logger->info('Auth Script Starting');

$auth=new MailAuth($logger);
$auth->setMailServerUrl('MySMTPServerHostName');
$auth->setServerType('SMTP');
$auth->setSmtpLocalHost('MyLocalHostName');
$auth->setTimeOut(10);
$auth->setSslCheck(false);
$auth->setUsername('MyUserName');
$auth->setPassword('MyPassword');
$result=$auth->authenticate();
var_dump($result);
