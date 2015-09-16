# A cURL extension in Sourcemod #

A free and easy-to-use client-side URL transfer library, supporting DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP. libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form based upload, proxies, cookies, user+password authentication (Basic, Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling and more!

http://curl.haxx.se/

http://www.sourcemod.net/

http://forums.alliedmods.net/showthread.php?t=152216

<br /><br />
v1.3.0.0 (released)
  * Update libcurl to 7.23.1
  * Update libssh2 to 1.3.0
  * Add CURLOPT`_*` from new libcurl version
  * Add `SendRecv_Act_GOTO_SEND_NO_WAIT & SendRecv_Act_GOTO_RECV_NO_WAIT`
<br />
v1.2.0.0 (released)
  * Add curl\_easy\_setopt\_function
  * Add CURLOPT\_WRITEFUNCTION, CURLOPT\_READFUNCTION support
  * Update smtp example
  * Add a example for CURLOPT\_WRITEFUNCTION
<br />
v1.1.0.0 (released)
  * All handles no more automately close, should close it manually
  * Add curl\_set\_send\_timeout, curl\_set\_recv\_timeout
  * Add udp support
  * Add a udp example
  * Update self test & examples
<br />
v1.0.0.0 (released)
  * Initial Release