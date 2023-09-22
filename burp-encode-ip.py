# -*- coding: utf-8 -*-
from burp import IBurpExtender
from javax.swing import BoxLayout
from burp import IBurpCollaboratorClientContext
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from javax.swing import JMenuItem
from java.util import ArrayList
from java.net import URLEncoder
from javax.swing import JMenuItem, JOptionPane, JDialog, JTextArea, JButton, JScrollPane
from java.awt import BorderLayout
import socket
import sys
from javax.swing import JLabel
import re
from javax.swing import JTextField
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from javax.swing import JPanel, JEditorPane
from javax.swing import Box
from java.awt import BorderLayout
from javax.swing.border import EmptyBorder

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._collaboratorClient = callbacks.createBurpCollaboratorClientContext()
        sys.stdout = callbacks.getStdout()  # Redirige stdout a la pestaña de alertas de Burp
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Encode IP")
        callbacks.registerContextMenuFactory(self)
        print("Encode IP - v1.4")
        print("by Eric Labrador")
        print("")
        print("The documentation can be found at https://github.com/e1abrador/Burp-Encode-IP/blob/main/README.md")
        print("If you ever see anything in the Errors tab, please raise an issue on Github so I can fix it!")

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Unicode Encoding (URL Encoded)", actionPerformed=self.encode_ip))
        menu_list.add(JMenuItem("Unicode Encoding (Copy to Clipboard)", actionPerformed=self.encode_ip_unicode))
        menu_list.add(JMenuItem("IPv4 on IPv6 Unicode Encoding (URL Encoded)", actionPerformed=self.apply_unicode_encoding))
        menu_list.add(JMenuItem("IPv4 on IPv6 Encoding (Show and Copy to Clipboard)", actionPerformed=self.show_and_encode_ipv4_to_ipv6))
        menu_list.add(JMenuItem("Class B Encoding", actionPerformed=self.class_b_encoding))
        menu_list.add(JMenuItem("Class A Encoding", actionPerformed=self.class_a_encoding))
        menu_list.add(JMenuItem("Hex Encoding", actionPerformed=self.hex_encoding))
        menu_list.add(JMenuItem("Hex w/o dots", actionPerformed=self.hex_no_dots_encoding))
        menu_list.add(JMenuItem("Hex Encoding v1", actionPerformed=self.hex_v1_encoding))  
        menu_list.add(JMenuItem("Hex Encoding v2", actionPerformed=self.hex_v2_encoding))  
        menu_list.add(JMenuItem("Octal Encoding", actionPerformed=self.octal_encoding))  
        menu_list.add(JMenuItem("Octal with 0s Encoding", actionPerformed=self.octal_with_zeros_encoding))
        menu_list.add(JMenuItem("Mixed Encoding", actionPerformed=self.mixed_encoding)) 
        menu_list.add(JMenuItem("Decimal Integer Encoding", actionPerformed=lambda _: self.integer_encoding()))
        menu_list.add(JMenuItem("Insert Collaborator IPv6 payload", actionPerformed=self.domain_ipv6))
        menu_list.add(JMenuItem("Insert DNS Rebinding payload", actionPerformed=lambda _: self.insert_dns_rebinding_payload()))
        menu_list.add(JMenuItem("All", actionPerformed=self.encode_all))
        menu_list.add(JMenuItem("Help", actionPerformed=self._tabHelpUI))

        return menu_list  # Agregar esta línea

    def _tabHelpUI(self, event):
        dialog = JDialog()
        dialog.setSize(1000, 1000)  # Adjust size as necessary
        dialog.setLayout(BorderLayout())
        
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        editorPaneInfo = JEditorPane()
        editorPaneInfo.setEditable(False)
        editorPaneInfo.setContentType("text/html")

        htmlString = "<html><body><p><b>Author:</b>\t\t\tEric Labrador Sainz</p><p><b>Github:</b>\t\t\thttps://github.com/e1abrador/Burp-Encode-IP/</p>\t\t<p><b>Issues with the extension:</b> https://github.com/e1abrador/Burp-Encode-IP/issues/new</p>\t\t<p><b>Ideas:</b> https://github.com/e1abrador/Burp-Encode-IP/pulls</p>"
        htmlString += """
<h1>About</h1>\n<p>This extension will encode an IP address into a bunch of less known encoding techniques.</p>\n<p>This technique is focused on testing vulnerabilities such as <b>SSRF</b> [<b><i>Server-Side Request Forgery</b></i>], <b>Open Redirect</b> or <b>RFI</b> [<b><i>Remote File Inclusion</b></i>].</p>
<h1>Prerequisites</h1>
<p>In order to be able to use Unicode encoding functions you need to change the default Burp Suite font to Monospaced (or any other supporting Unicode characters), if the font is not changed you won't be able to use Unicode characters on Burp.</p>
<p></p>
 <p><img width=\"1000\" alt=\"Change font\" src=\"https://github.com/e1abrador/Burp-Encode-IP/assets/74373745/542e8648-91f4-4eab-a0cc-8eaa25ce5a27\"><br/><br/></p>
<h1>Usage</h1>
The usage of the extension is very easy, first you need to highlight an IP address:
<p></p>
 <p><img width=\"1000\" alt=\"Change font\" src=\"https://github.com/e1abrador/Burp-Encode-IP/assets/74373745/8acbee56-aa62-4852-8d65-1f8205e698fb\"><br/><br/></p>
<p></p>
<p>Then, you must just right-click and select the encoding you want to use. On most encodings the auto substitution works properly, but i did not found any way of automating that action with Unicode characters.</p>
<p></p>
 <p><img width=\"1000\" alt=\"Change font\" src=\"https://github.com/e1abrador/Burp-Encode-IP/assets/74373745/a8a486dc-ad77-45f0-a464-b4dcf20ca2ee\"><br/><br/></p>
<p></p>
<h1>Supported Encodes</h1>
<p><b><i>Unicode Encoding (Url Encoded) </b></i>-> Will convert an IP address First to Unicode format and then to URL Encode.</p>
<p><b><i>Unicode Encoding (Copy to Clipboard) </b></i>-> Wil convert the IP address to its Unicode version. Could you paste it on the same action? I did not find any way on Burp Suite to paste Unicode from the script, therefore I added a popup window that will let the user copy the characters on the clipboard and then paste it directly to Burp Suite.</p>
<p><b><i>IPv4 on IPv6 Unicode Encoding (URL Encoded)</b></i> -> Will convert an IP address to the following format (URL Encoded): <i>[::ffff:unicoded-ip-address-here]:80</i>. This can be useful to bypass some filters / WAF rules.</p>
<p><b><i>IPv4 on IPv6 Unicode Encoding (Copy to Clipboard)</b></i> -> As well as <b><i>Unicode Encoding (Copy to Clipboard)</i></b> i did not find a way to paste Unicode special characters on Burp Suite (Repeater and Proxy) so when clicking this option the user will see a popup window to copy and paste the generated payload.</p>
<p><b><i>Class B Encoding</b></i> -> Will convert the IP address in two parts: the first two octets are preserved as is and the last two are combined into a single value.</p>
<p><b><i>Class A Encoding</b></i> -> Will preserve the first octet as is and will combine the remaining three octets into a single value.</p>
<p><b><i>Hex Encoding</b></i> -> Will convert the octets of the IP address to hexadecimal values.</p>
<p><b><i>Hex w/o dots</b></i> -> Will convert the IP address to a single hexadecimal value without dots.</p>
<p><b><i>Hex Encoding v1</b></i> -> Will convert the first octet to hex and combine the remaining three octets into a single hexadecimal value.</p>
<p><b><i>Hex Encoding v2</b></i> -> Will convert the first two octets to individual hexadecimal values, and the last two octets are combined into a single hexadecimal value.</p>
<p><b><i>Octal Encoding</b></i> -> Will convert the octets of the IP address to octal values.</p>
<p><b><i>Octal with 0s Encoding</b></i> -> Will convert each octet into a zero-padded octal value.</p>
<p><b><i>Mixed Encoding</b></i> -> Will treats the entire IP address as a single integer value. Each octet of the IP address is interpreted as a byte, and these bytes are combined to form a single integer.</p>
<p><b><i>Collaborator in IPv6</b></i> -> Will convert a collaborator URL (automatically obtained from Burp API) and will convert it to a IPv6 valid domain.
<p><b><i>DNS Rebinding</b></i> -> Will generate a domain configured with the DNS Rebinding technique (thanks to https://twitter.com/taviso). In any case, there's the possibility of adding a custom domain (Note that in order for this to work, this https://github.com/taviso/rbndr must be configured first).
<p><b><i>All</b></i> -> Will generate a popup window that will contain the IP address encoded in all configured conversions currently existing on the extension.</p>
<h1>Advisory</h1>
<p>This Burp Suite extension should be used for authorized penetration testing and/or educational purposes only. <b><i>Any misuse of this software will not be the responsibility of the author or of any other collaborator.</i></b> Use it at your own networks and/or with the network owner's permission.</p>
<p>Good luck and good hunting! If you really love the tool (or any others), or they helped you find an awesome bounty, consider BUYING ME A COFFEE! [<b><i>https://www.buymeacoffee.com/e1abrador</i></b>] (I could use the caffeine!)</p>
"""
        editorPaneInfo.setText(htmlString)

        # Create a JScrollPane and add your JEditorPane to it
        scrollPane = JScrollPane(editorPaneInfo)
        panel.add(scrollPane, BorderLayout.CENTER)
        dialog.add(panel)

        dialog.setVisible(True)

    def insert_dns_rebinding_payload(self):
        # Create a popup with three fields: two for IP addresses and one for domain
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        label1 = JLabel("Enter IP Address 1:")
        ipField1 = JTextField(15)
    
        label2 = JLabel("Enter IP Address 2:")
        ipField2 = JTextField(15)
    
        label3 = JLabel("Enter Domain (optional, default rbndr.us):")
        domainField = JTextField(15)

        panel.add(label1)
        panel.add(ipField1)
        panel.add(Box.createVerticalStrut(10))
    
        panel.add(label2)
        panel.add(ipField2)
        panel.add(Box.createVerticalStrut(10))
    
        panel.add(label3)
        panel.add(domainField)
    
        panel.setBorder(EmptyBorder(10,10,10,10))

        result = JOptionPane.showConfirmDialog(None, panel, "Insert DNS Rebinding payload", JOptionPane.OK_CANCEL_OPTION)

        if result == JOptionPane.OK_OPTION:
            ip1 = ipField1.getText()
            ip2 = ipField2.getText()

            # If the domain field is empty, use 'rbndr.us'. Otherwise, use the domain provided by the user.
            custom_domain = domainField.getText() or "rbndr.us"

            if self.valid_ip(ip1) and self.valid_ip(ip2):
                domain = self.convert_dotted_quad(ip1) + "." + self.convert_dotted_quad(ip2) + "." + custom_domain
                self.insert_into_request(domain)
            else:
                print("<invalid>")

    def valid_ip(self, addr):
        pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        return pattern.match(addr) is not None

    def convert_dotted_quad(self, addr):
        ip_parts = addr.split('.')
        hex_parts = [format(int(part), '02x') for part in ip_parts]
        return ''.join(hex_parts)

    def insert_into_request(self, domain):
        http_traffic = self.context.getSelectedMessages()
        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedData = self._helpers.bytesToString(request)
        
            # Simplemente añadir el dominio al final de la petición
            modifiedData = selectedData + domain
        
            traffic.setRequest(self._helpers.stringToBytes(modifiedData))


    def integer_encoding(self):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_integer(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_integer(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
        
        encoded = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
        
        return str(encoded)

    def mixed_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_mixed(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_mixed(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
        
        encoded = ip_parts[0] + '.0x%x.' % int(ip_parts[1]) + '%012o.' % int(ip_parts[2]) + '0x%x' % int(ip_parts[3])
        
        return encoded

    def octal_with_zeros_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_octal_with_zeros(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_octal_with_zeros(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")

        encoded = '.'.join('%012o' % int(part) for part in ip_parts)
        return encoded

    def octal_with_zeros_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_octal_with_zeros(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_octal_with_zeros(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")

        encoded = '.'.join('%012o' % int(part) for part in ip_parts)
        return encoded

    def octal_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_octal(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_octal(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")

        encoded = '.'.join('0%o' % int(part) for part in ip_parts)
        return encoded

    def hex_v2_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_hex_v2(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_hex_v2(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")

        # Hex Encoding v2: convert the first two parts individually to hex, 
        # then convert the last two parts combined to hex
        encoded = '0x%x.0x%x.0x%04x' % (int(ip_parts[0]), int(ip_parts[1]), int(ip_parts[2])*256 + int(ip_parts[3]))

        return encoded

    def hex_v1_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_hex_v1(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_hex_v1(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")

        # Hex Encoding v1: take the first part of IP separately and rest combined
        encoded = '0x%x.' % int(ip_parts[0]) + '0x' + ''.join('%02x' % int(part) for part in ip_parts[1:])

        return encoded

    def hex_no_dots_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_hex_no_dots(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_hex_no_dots(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
        
        # Codificación hexadecimal sin puntos
        encoded = ''.join('%02x' % int(part) for part in ip_parts)
        
        return '0x' + encoded

    def hex_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_hex(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_hex(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
        encoded = '.'.join('0x%x' % int(part) for part in ip_parts)
        return encoded

    def show_and_encode_ipv4_to_ipv6(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.transform_ip_to_unicode(selectedIP)
                self.show_popup_dialog("IPv4 on IPv6 Encoded IP", encodedIP)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def transform_ip_to_unicode(self, ip):
        unicode_nums = [u'⓪', u'①', u'②', u'③', u'④', u'⑤', u'⑥', u'⑦', u'⑧', u'⑨']
        ip_parts = ip.split('.')

        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")

        encoded = u"[::ⓕⓕⓕⓕ:"
        for part in ip_parts:
            for digit in part:
                if digit.isdigit():
                    encoded += unicode_nums[int(digit)]
                else:
                    encoded += digit
            encoded += u"。"
        encoded = encoded.rstrip(u"。") + u"]:80"  # remove the last dot and append ]:80

        return encoded

    def encode_ip_unicode(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.convert_ip_to_unicode(selectedIP)
                self.show_popup_dialog("Encoded IP", encodedIP)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def convert_ip_to_unicode(self, ip):
        unicode_ip = ""
        for part in ip.split("."):
            for digit in part:
                if digit == '0':
                    unicode_ip += u'\u24EA'  # caso especial para 0
                else:
                    unicode_ip += unichr(0x245F + int(digit))  # 0x2460 es para 1, por lo que 0x245F + dígito da la asignación correcta
            unicode_ip += u'\u3002'  # Unicode para punto final ideográfico
        return unicode_ip[:-1]

    def show_popup_dialog(self, title, message):
        dialog = JDialog()
        dialog.title = title
        dialog.setModal(True)

        text_area = JTextArea(message)
        text_area.editable = False
        scroll_pane = JScrollPane(text_area)

        copy_button = JButton("Copy")
        #copy_button.addActionListener(lambda event: self.copy_to_clipboard(message))
        copy_button.addActionListener(lambda event: self.copy_to_clipboard())


        dialog.add(scroll_pane, BorderLayout.CENTER)
        dialog.add(copy_button, BorderLayout.PAGE_END)

        dialog.pack()
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)


    def copy_to_clipboard(self):
        text_to_copy = "\n".join(self.encodings_to_copy)
        selection = StringSelection(text_to_copy)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(selection, None)


    def encode_ip(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_unicode_url(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_unicode_url(self, ip):
        unicode_ip = ""
        for part in ip.split("."):
            for digit in part:
                if digit == '0':
                    unicode_ip += u'\u24FF'  # caso especial para 0
                else:
                    unicode_ip += unichr(0x245F + int(digit))  # 0x2460 es para 1, por lo que 0x245F + dígito da la asignación correcta
            unicode_ip += u'\u3002'  # Unicode para punto final ideográfico
        return URLEncoder.encode(unicode_ip[:-1].encode('utf-8'), "UTF-8")


    def encode_ipv4_on_ipv6_url(self, ip):
        encoded_ip = self.transform_ip_to_unicode(ip)
        return URLEncoder.encode(encoded_ip.encode('utf-8'), "UTF-8").replace("+", "%20") if encoded_ip else None

    
    def apply_unicode_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.transform_ip_to_unicodex(selectedIP)
                encodedIP = self.convert_unicode_to_urlencoding(encodedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def transform_ip_to_unicodex(self, ip):
        unicode_nums = ['⓪', '①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧', '⑨']
        ip_parts = ip.split('.')

        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")

        encoded = "[::ⓕⓕⓕⓕ:"
        for part in ip_parts:
            for digit in part:
                encoded += unicode_nums[int(digit)]
            encoded += "。"
        encoded = encoded.rstrip("。") + "]:80"  # remove the last dot and append ]:80

        return encoded

    def convert_unicode_to_urlencoding(self, s):
        res = ""
        for char in s:
            if ord(char) > 127:
                res += "%" + format(ord(char), 'x').zfill(2)
            else:
                res += char
        return res

    def class_b_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_class_b(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_class_b(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
        
        first_two = ".".join(ip_parts[:2])
        last_two = int(ip_parts[2]) * 256 + int(ip_parts[3])
        
        return first_two + '.' + str(last_two)
    
    def class_a_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_class_a(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass

    def encode_ip_class_a(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
        
        first_one = ip_parts[0]
        last_three = int(ip_parts[1]) * 65536 + int(ip_parts[2]) * 256 + int(ip_parts[3])
        
        return first_one + '.' + str(last_three)

    @staticmethod
    def convert_ipv4_to_ipv6(ipv4):
        ipv4_parts = ipv4.split('.')
        ipv6_parts = []

        # Agrupar los octetos en pares y convertirlos a hexadecimal
        for i in range(0, len(ipv4_parts), 2):
            hex_part = hex(int(ipv4_parts[i]) << 8 | int(ipv4_parts[i + 1]))[2:]
            ipv6_parts.append(hex_part)

        # Unir los pares convertidos y añadir el prefijo IPv4-mapped
        return "::ffff:" + ':'.join(ipv6_parts)

    def domain_ipv6(self, event):
        # Generar una URL de colaborador
        collaboratorPayload = self._collaboratorClient.generatePayload(True)
        print("Collaborator payload:", collaboratorPayload)

        path_string = collaboratorPayload.split('.')[0]

        # Aquí tienes el dominio generado por Burp Collaborator
        domain_to_query = collaboratorPayload

        # Obtiene el tráfico HTTP seleccionado
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            specific_part = self._helpers.bytesToString(request[start:end])

            ipv4_addresses = self.get_ipv4_from_domain(domain_to_query)
            unique_ipv4 = set(ipv4_addresses)

            for ipv4 in unique_ipv4:
                ipv6 = self.convert_ipv4_to_ipv6(ipv4)
                url = "http://[{0}]/{1}".format(ipv6, path_string)
                url_bytes = self._helpers.stringToBytes(url)
                newRequest = request[:start] + url_bytes + request[end:]
                traffic.setRequest(newRequest)

    def get_ipv4_from_domain(self, domain_name):
        try:
            ipv4_addresses = [ip[4][0] for ip in socket.getaddrinfo(domain_name, None, family=socket.AF_INET)]
            return ipv4_addresses
        except Exception as e:
            print("An error occurred: " + str(e))

            return []


    def encode_all(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                # Unicode encoding
                unicode_encoded_IP = self.convert_ip_to_unicode(selectedIP)
                # IPv4 on IPv6 encoding
                ipv6_encoded_IP = self.transform_ip_to_unicode(selectedIP)
                # Unicode IP (urlencoded)
                unicode_ip_urlencoded = self.encode_ip_unicode_url(selectedIP)
                # IPv4 on IPv6 encoding (URL)
                ipv6_unicode_url_encoding = self.encode_ipv4_on_ipv6_url(selectedIP)
                # Class B
                class_b_encoding_url_x = self.encode_ip_class_b(selectedIP)
                # Class A
                class_a_encoding_url_x = self.encode_ip_class_a(selectedIP)
		# Hex encoding 
		hex_encoding_x = self.encode_ip_hex(selectedIP)
		# Hex without dots
		hex_without_dots = self.encode_ip_hex_no_dots(selectedIP)
		# Hex v1
		hex_v1_enc = self.encode_ip_hex_v1(selectedIP)
		# hex v2
		hex_v2_enc = self.encode_ip_hex_v2(selectedIP)
		# octal
		octal_enc = self.encode_ip_octal(selectedIP)
		# octal with 0s
		octal_w_0 = self.encode_ip_octal_with_zeros(selectedIP)
		# mixed encoding
		mixed_enc = self.encode_ip_mixed(selectedIP)
		# Decimal intiger
		decimal_intiger = self.encode_ip_integer(selectedIP)

                # Guardar los encodings en una lista
                self.encodings_to_copy = [unicode_ip_urlencoded, unicode_encoded_IP, ipv6_encoded_IP, ipv6_unicode_url_encoding, class_b_encoding_url_x, class_a_encoding_url_x, hex_encoding_x, hex_without_dots, hex_v1_enc, hex_v2_enc, octal_enc, octal_w_0, mixed_enc, decimal_intiger]

                # Generar el texto final para mostrar
                final_text_to_display = u"Unicode Encoding (URL Encoded): {}\nUnicode Encoding: {}\nIPv4 on IPv6 Encoding: {}\nIPv4 on IPv6 Encoding (URL Encoded): {}\nClass B Encoding: {}\nClass A Encoding: {}\nHex Encoding: {}\nHex w/o dots: {}\nHex Encoding v1: {}\nHex Encoding v2: {}\nOctal Encode: {}\nOctal Encode with 0s: {}\nMixed Encoding: {}\nDecimal Intiger Encoding: {}".format(
                    *self.encodings_to_copy)

                # Mostrar
                self.show_popup_dialog("All Encodings - {}".format(selectedIP), final_text_to_display)

            except socket.error:
                print("Non IPv4 detected. Please select an IPv4 to perform a correct encoding. ")
                pass
