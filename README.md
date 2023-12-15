## About

This extension will encode an IP address into a bunch of less known encoding techniques.

This technique is focused on testing vulnerabilities such as SSRF [Server-Side Request Forgery], Open Redirect or RFI [Remote File Inclusion].

## TL;DR

### Easy Install

If you have Burp Pro it is possible to install directly on BApp:

![image](https://github.com/e1abrador/Burp-Encode-IP/assets/74373745/3cb11dfd-1fba-4ec2-ad5a-242d9a2e12d5)

Don't forget to rate the extension with ⭐⭐⭐⭐⭐ stars ;)

### Installation

Go to the Extensions <b>-></b> Installed <b>-></b> Add <b>-></b> burp-encode-ip.py

In order to use Unicode characters please follow the steps in the video:

[change_burp_font.webm](https://github.com/e1abrador/Burp-Encode-IP/assets/74373745/6cc9b169-766f-4693-aab3-9bb4977f1e60)

## Using

[Demo.webm](https://github.com/e1abrador/Burp-Encode-IP/assets/74373745/a97b1425-518c-4515-944a-743aea6d9745)

## Encodes

<b><i>Unicode Encoding (Url Encoded)</i></b> -> Will convert an IP address <b>First</b> to Unicode format and then to <b>URL Encode</b>.

<b><i>Unicode Encoding (Copy to Clipboard)</i></b> -> Wil convert the IP address to its Unicode version. Could you paste it on the same action? I did not find any way on Burp Suite to paste Unicode from the script, therefore I added a popup window that will let the user copy the characters on the clipboard and then paste it directly to Burp Suite.

<b><i>IPv4 on IPv6 Unicode Encoding (URL Encoded)</i></b> -> Will convert an IP address to the following format (URL Encoded): ``[::ⓕⓕⓕⓕ:unicoded-ip-address-here]:80``. This can be useful to bypass some filters / WAF rules. [Twitter PoC](https://twitter.com/HusseiN98D/status/1681347329243201553)

<b></i>IPv4 on IPv6 Unicode Encoding (Copy to Clipboard)</i></b> -> As well as ``Unicode Encoding (Copy to Clipboard)`` i did not find a way to paste Unicode special characters on Burp Suite (Repeater and Proxy) so when clicking this option the user will see a popup window to copy and paste the generated payload.

<b><i>Class B Encoding</i></b> -> Will convert the IP address in two parts: the first two octets are preserved as is and the last two are combined into a single value.

<b><i>Class A Encoding</i></b> -> Will preserve the first octet as is and will combine the remaining three octets into a single value.

<b><i>Hex Encoding</i></b> -> Will convert the octets of the IP address to hexadecimal values.

<b><i>Hex w/o dots</i></b> -> Will convert the IP address to a single hexadecimal value without dots.

<b><i>Hex Encoding v1</i></b> -> Will convert the first octet to hex and combine the remaining three octets into a single hexadecimal value.

<b><i>Hex Encoding v2</i></b> -> Will convert the first two octets to individual hexadecimal values, and the last two octets are combined into a single hexadecimal value.

<b><i>Octal Encoding</i></b> -> Will convert the octets of the IP address to octal values.

<b><i>Octal with 0s Encoding</i></b> -> Will convert each octet into a zero-padded octal value.

<b><i>Mixed Encoding</i></b> -> Will treat the entire IP address as a single integer value. Each octet of the IP address is interpreted as a byte, and these bytes are combined to form a single integer.

<b><i>Collaborator in IPv6</b></i> -> Will use a collaborator URL (automatically obtained from Burp API) and will convert it to an IPv6 valid domain.

<b><i>DNS Rebinding</b></i> -> Will generate a domain configured with the DNS Rebinding technique (thanks to https://twitter.com/taviso). In any case, there's the possibility of adding a custom domain (Note that in order for the custom domain to work, this https://github.com/taviso/rbndr must be configured first).

<b><i>All</i></b> -> Will generate a popup window that will contain the IP address encoded in all configured conversions currently existing on the extension. 

Good luck and good hunting!
If you really love the tool (or any others), or they helped you find an awesome bounty, consider [BUYING ME A COFFEE!](https://www.buymeacoffee.com/e1abrador) ☕ (I could use the caffeine!)

⚪ e1abrador

<a href='https://www.buymeacoffee.com/e1abrador' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>

## TODO

- Implement random number of octets encoding, in example: 0251.254.169.254 = 169.254.169.254.

## Changelog

**25/08/2025** -> Update integrating DNS Rebinding technique.

## Advisory

This Burp Suite extension should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.
