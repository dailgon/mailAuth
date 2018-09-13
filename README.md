# mailAuth

## Overview

PHP Class to authenticate a user against a mail server.

## Specification

Allow setting of auth type : POP3, POP3S, IMAP, IMAPS, SMTP, SMTPS.

Take a username and a password and then attempt a login to the specified mail server.

If login is successful, then return true, else return false.


SMTP authentication function adapted from :
http://support.webecs.com/kb/a390/php-mail-script-with-smtp-authentication.aspx


## Usage

| Configurable settings | Default Value   | Description                                                                                                                                                                                               |
|:----------------------|:----------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| mailServerUrl         | NONE            | Mailserver URL                                                                                                                                                                                            |
| serverPort            | NONE            | Mailserver Port number, normally automatically set after by setting the serverType, but can be overridden if required                                                                                     |
| serverType            | NONE            | Service to use for authentication POP3/POP3S/IMAP/IMAPS/SMTP/SMTPS                                                                                                                                        |
| serverTypes           | Array of Types  | Built in list of valid services for authentication                                                                                                                                                        |
| errors                | Array of Errors | List of all error codes, there description and some help text on what the issue may be                                                                                                                    |
| username              | NONE            | Set to the username to be used for authentication                                                                                                                                                         |
| password              | NONE            | Set to the password to be used for authentication                                                                                                                                                         |
| passwordType          | plain           | Currently on 'plain' is used, possible future enhancement to allow form based password encryption                                                                                                         |
| passwordTypes         |                 | List of supported passwordTypes, currently only 'plain' is supported                                                                                                                                      |
| logger                | Null Logger     | \Monolog\Logger if passed to constructor, this is used for all logging                                                                                                                                    |
| sslCheck              | true            | If true, then perform SSL verification on the connection.  **NOTE** If using POP or IMAP, this should be set to 'false' as some bug causes PHP imap_open to still check SSL when using non-ssl connection |
| authenticated         | EMPTY           | Status of the authentication, set to True after user sucsesfully authenticates or False otherwise                                                                                                         |
| timeOut               | 30              | Time out for SMTP connections, best to set this to a low value, as the authentication script will wait till this timeout if there is an issue connecting to the server                                    |
| newLine               | \r\n            | End Of Line terminator to use in SMTP comunications                                                                                                                                                       |
| smtpLocalHost         | NONE            | Local hostname for SMTP authentication, not currently used, will most likely be removed in a future revision.                                                                                             |

##### Setup Logging, not required but good for debug
```
$logger=new Logger('auth');
$logger->pushHandler(new StreamHandler(__DIR__.'/auth.log', LOGGER::DEBUG));
$logger->info('Auth Script Starting');
```
After authenticate() has been called, you can check the result of the authentication with :
```
$result=$auth->authenticated;
```

#### SMTP Authentication
```
$auth=new MailAuth($logger);
$auth->setMailServerUrl('MySMTPServerHostName');
$auth->setServerType('SMTP');
$auth->setSmtpLocalHost('MyLocalHostName');
$auth->setTimeOut(10);
$auth->setSslCheck(false);
$auth->setUsername('MyUserName');
$auth->setPassword('MyPassword');
$result=$auth->authenticate();
```

#### SMTPS Authentication
```
$auth=new MailAuth($logger);
$auth->setMailServerUrl('MySMTPServerHostName');
$auth->setServerType('SMTPS');
$auth->setSmtpLocalHost('MyLocalHostName');
$auth->setTimeOut(10);
$auth->setSslCheck(true);
$auth->setUsername('MyUserName');
$auth->setPassword('MyPassword');
$result=$auth->authenticate();
```
#### POP3 Authentication
```
$auth=new MailAuth($logger);
$auth->setMailServerUrl('MyPOPServerHostName');
$auth->setServerType('POP3');
$auth->setSslCheck(false);
$auth->setUsername('MyUserName');
$auth->setPassword('MyPassword');
$result=$auth->authenticate();
```
#### POP3S Authentication
```
$auth=new MailAuth($logger);
$auth->setMailServerUrl('MyPOPServerHostName');
$auth->setServerType('POP3S');
$auth->setSslCheck(true);
$auth->setUsername('MyUserName');
$auth->setPassword('MyPassword');
$result=$auth->authenticate();
```
#### IMAP Authentication
```
$auth=new MailAuth($logger);
$auth->setMailServerUrl('MyIMAPServerHostName');
$auth->setServerType('IMAP');
$auth->setSslCheck(false);
$auth->setUsername('MyUserName');
$auth->setPassword('MyPassword');
$result=$auth->authenticate();
```
#### IMAPS Authentication
```
$auth=new MailAuth($logger);
$auth->setMailServerUrl('MyIMAPServerHostName');
$auth->setServerType('IMAPS');
$auth->setSslCheck(true);
$auth->setUsername('MyUserName');
$auth->setPassword('MyPassword');
$result=$auth->authenticate();
```
