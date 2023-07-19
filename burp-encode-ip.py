# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from javax.swing import JMenuItem
from java.util import ArrayList
from java.net import URLEncoder
import socket
import sys

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        sys.stdout = callbacks.getStdout()  # Redirige stdout a la pestaña de alertas de Burp
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Encode IP")
        callbacks.registerContextMenuFactory(self)
        print("Extension loaded successfully.")

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Unicode Encoding", actionPerformed=self.encode_ip))
        menu_list.add(JMenuItem("Class B Encoding", actionPerformed=self.class_b_encoding))
        menu_list.add(JMenuItem("Class A Encoding", actionPerformed=self.class_a_encoding))
        menu_list.add(JMenuItem("No Dots Encoding", actionPerformed=self.no_dots_encoding))
        menu_list.add(JMenuItem("Hex Encoding", actionPerformed=self.hex_encoding))
        menu_list.add(JMenuItem("Hex w/o dots", actionPerformed=self.hex_no_dots_encoding))
        menu_list.add(JMenuItem("Hex Encoding v1", actionPerformed=self.hex_v1_encoding))  
        menu_list.add(JMenuItem("Hex Encoding v2", actionPerformed=self.hex_v2_encoding))  
        menu_list.add(JMenuItem("Octal Encoding", actionPerformed=self.octal_encoding))  
        menu_list.add(JMenuItem("Octal with 0s Encoding", actionPerformed=self.octal_with_zeros_encoding))
        menu_list.add(JMenuItem("Mixed Encoding", actionPerformed=self.mixed_encoding)) 
        menu_list.add(JMenuItem("Decimal Integer Encoding", actionPerformed=lambda _: self.integer_encoding()))

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

    def no_dots_encoding(self, event):
        http_traffic = self.context.getSelectedMessages()
        bounds = self.context.getSelectionBounds()
        start, end = bounds[0], bounds[1]

        for traffic in http_traffic:
            request = traffic.getRequest()
            selectedIP = self._helpers.bytesToString(request[start:end])

            try:
                socket.inet_aton(selectedIP)
                encodedIP = self.encode_ip_no_dots(selectedIP)
                encodedBytes = self._helpers.stringToBytes(encodedIP)
                newRequest = request[:start] + encodedBytes + request[end:]
                traffic.setRequest(newRequest)
            except socket.error:
                print("Not a valid IP.")
                pass

    def encode_ip_no_dots(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address")
        
        encoded = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
        
        return str(encoded)

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
