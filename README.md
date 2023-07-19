## About

This extension will encode an IP address first to Unicode and then to URL encoding. The extension needs to URL encode the IP address since Burp Suite doesn't accept Unicode on the request boxes.

This technique is focused on testing how the server normalizes Unicode characters (where an IP address is needed), such as SSRF [Server-Side Request Forgery], Open Redirect or RFI [Remote File Inclusion].

## TL;DR

### Installation

Go to the Extensions <b>-></b> Installed <b>-></b> Add <b>-></b> burp-encode-ip.py

## Using

Let's say we have the following request:

![image](https://github.com/e1abrador/Burp-Unicode-IP/assets/74373745/8a3a958b-0e3e-4eee-8bcb-05db0ffcea78)

If we would need to face a WAF or a web app blacklist, we could use this extension to bypass those filters and test the vulnerability we are looking for.

First, select the IP address you want to encode:

![image](https://github.com/e1abrador/Burp-Unicode-IP/assets/74373745/caa4da8c-89a1-4d39-a0e8-db1c5ee91651)

Then right click <b>-></b> Extensions <b>-></b> \<choose any encoding\>

![image](https://github.com/e1abrador/Burp-Encode-IP/assets/74373745/04b052e1-15b9-4876-9830-0ccc45eaa457)

This would be the result:

![image](https://github.com/e1abrador/Burp-Unicode-IP/assets/74373745/e846a157-70f8-4e6a-a909-74ea60ccccd5)

When viewing the result on Cyber Chef (https://gchq.github.io/CyberChef/) and selecting Magic on the left bar, it is possible to see that the result is ①⑨②。①⑥⑧。①。①①	, which is the Unicode version of the selected IP address:

![image](https://github.com/e1abrador/Burp-Unicode-IP/assets/74373745/be513038-ca00-41cb-aa8c-1a150eee0d85)

## Encodes

<b>Unicode Encoding:</b> This method encodes the IP address into a Unicode string.

<b>Class B Encoding:</b> In this method, the IP address is divided into two parts: the first two octets are preserved as is and the last two are combined into a single value.

<b>Class A Encoding:</b> This method preserves the first octet as is and combines the remaining three octets into a single value.

<b>No Dots Encoding:</b> This method treats the entire IP address as a single integer value.

<b>Hex Encoding:</b> The octets of the IP address are converted to hexadecimal values.

<b>Hex w/o dots:</b> This method converts the IP address to a single hexadecimal value without dots.

<b>Hex Encoding v1:</b> This method converts the first octet to hex and combines the remaining three octets into a single hexadecimal value.

<b>Hex Encoding v2:</b> This method converts the first two octets to individual hexadecimal values, and the last two octets are combined into a single hexadecimal value.

<b>Octal Encoding:</b> The octets of the IP address are converted to octal values.

<b>Octal with 0s Encoding:</b> This method converts each octet into a zero-padded octal value.

<b>Mixed Encoding:</b> This method applies a mix of encodings to different parts of the IP address.

<b>Decimal Integer Encoding:</b> This method treats the entire IP address as a single integer value. Each octet of the IP address is interpreted as a byte, and these bytes are combined to form a single integer.

Good luck and good hunting!
If you really love the tool (or any others), or they helped you find an awesome bounty, consider [BUYING ME A COFFEE!](https://www.buymeacoffee.com/e1abrador) ☕ (I could use the caffeine!)

⚪ e1abrador

<a href='https://www.buymeacoffee.com/e1abrador' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
