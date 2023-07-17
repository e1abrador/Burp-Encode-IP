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
        sys.stdout = callbacks.getStdout()  # Redirect stdout to the Burp alerts tab
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Encode IP")
        callbacks.registerContextMenuFactory(self)
        print("Extension loaded successfully.")

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Encode IP", actionPerformed=self.encode_ip))
        return menu_list

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
                    unicode_ip += u'\u24FF'  # special case for 0
                else:
                    unicode_ip += unichr(0x245F + int(digit))  # 0x2460 is for 1, so 0x245F + digit gives correct mapping
            unicode_ip += u'\u3002'  # Unicode for ideographic full stop
        return URLEncoder.encode(unicode_ip[:-1].encode('utf-8'), "UTF-8")

