# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from javax.swing import JMenuItem
from java.util import ArrayList
from java.net import URLEncoder
import socket
import sys
from javax.swing import JMenuItem, JOptionPane, JDialog, JTextArea, JButton, JScrollPane
from java.awt import BorderLayout
import socket
import sys
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
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

        menu_list.add(JMenuItem("All", actionPerformed=self.encode_all))

        return menu_list

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
                print("Not a valid IP.")
                pass

    def encode_ip_integer(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")
        
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
                print("Not a valid IP.")
                pass

    def encode_ip_mixed(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")
        
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
                print("Not a valid IP.")
                pass

    def encode_ip_octal_with_zeros(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")

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
                print("Not a valid IP.")
                pass

    def encode_ip_octal_with_zeros(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")

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
                print("Not a valid IP.")
                pass

    def encode_ip_octal(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")

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
                print("Not a valid IP.")
                pass

    def encode_ip_hex_v2(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")

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
                print("Not a valid IP.")
                pass

    def encode_ip_hex_v1(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")

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
                print("Not a valid IP.")
                pass

    def encode_ip_hex_no_dots(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")
        
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
                print("Not a valid IP.")
                pass

    def encode_ip_hex(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")
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
                print("Not a valid IP.")
                pass

    def transform_ip_to_unicode(self, ip):
        unicode_nums = [u'⓪', u'①', u'②', u'③', u'④', u'⑤', u'⑥', u'⑦', u'⑧', u'⑨']
        ip_parts = ip.split('.')

        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")

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
		
                # Show all encodings in popup
                all_encodings = u"Unicode Encoding (URL Encoded): {}\nUnicode Encoding: {}\nIPv4 on IPv6 Encoding: {}\nIPv4 on IPv6 Encoding (URL Encoded): {}\nClass B Encoding: {}\nClass A Encoding: {}\nHex Encoding: {}\nHex w/o dots: {}\nHex Encoding v1: {}\nHex Encoding v2: {}\nOctal Encode: {}\nMixed Encoding: {}\nDecimal Intiger Encoding: {}".format(
                    unicode_ip_urlencoded, unicode_encoded_IP, ipv6_encoded_IP, ipv6_unicode_url_encoding, class_b_encoding_url_x, class_a_encoding_url_x, hex_encoding_x, hex_without_dots, hex_v1_enc, hex_v2_enc, octal_enc, mixed_enc, decimal_intiger)

                self.show_popup_dialog("All Encodings - {}".format(selectedIP), all_encodings)
            except socket.error:
                print("Not a valid IP.")
                pass

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
                print("Not a valid IP.")
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
        copy_button.addActionListener(lambda event: self.copy_to_clipboard(message))

        dialog.add(scroll_pane, BorderLayout.CENTER)
        dialog.add(copy_button, BorderLayout.PAGE_END)

        dialog.pack()
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)

    def copy_to_clipboard(self, text):
        selection = StringSelection(text)
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
                print("Not a valid IP.")
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
                print("Not a valid IP.")
                pass

    def transform_ip_to_unicodex(self, ip):
        unicode_nums = ['⓪', '①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧', '⑨']
        ip_parts = ip.split('.')

        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")

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
                print("Not a valid IP.")
                pass

    def encode_ip_class_b(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")
        
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
                print("Not a valid IP.")
                pass

    def encode_ip_class_a(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")
        
        first_one = ip_parts[0]
        last_three = int(ip_parts[1]) * 65536 + int(ip_parts[2]) * 256 + int(ip_parts[3])
        
        return first_one + '.' + str(last_three)
