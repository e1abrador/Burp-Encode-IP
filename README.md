## About

This extension will encode an IP address first to Unicode and then to URL encoding. The extension needs to URL encode the IP address since Burp Suite doesn't accept Unicode on the request boxes.

This technique is focused on testing how the server normalizes Unicode characters (where an IP address is needed), such as SSRF [Server-Side Request Forgery], Open Redirect or RFI [Remote File Inclusion].

## TL;DR

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

<b><i>Mixed Encoding</i></b> -> Will treats the entire IP address as a single integer value. Each octet of the IP address is interpreted as a byte, and these bytes are combined to form a single integer.

<b><i>All</i></b> -> Will generate a popup window that will contain the IP address encoded in all configured conversions currently existing on the extension. 


















Good luck and good hunting!
If you really love the tool (or any others), or they helped you find an awesome bounty, consider [BUYING ME A COFFEE!](https://www.buymeacoffee.com/e1abrador) ☕ (I could use the caffeine!)

⚪ e1abrador

<a href='https://www.buymeacoffee.com/e1abrador' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
