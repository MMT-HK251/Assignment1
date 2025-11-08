#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# WeApRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
daemon.response
~~~~~~~~~~~~~~~~~

This module provides a :class: `Response <Response>` object to manage and persist 
response settings (cookies, auth, proxies), and to construct HTTP responses
based on incoming requests. 

The current version supports MIME type detection, content loading and header formatting
"""
import datetime
import os
import mimetypes
from .dictionary import CaseInsensitiveDict

BASE_DIR = ""

class Response():   
    """The :class:`Response <Response>` object, which contains a
    server's response to an HTTP request.

    Instances are generated from a :class:`Request <Request>` object, and
    should not be instantiated manually; doing so may produce undesirable
    effects.

    :class:`Response <Response>` object encapsulates headers, content, 
    status code, cookies, and metadata related to the request-response cycle.
    It is used to construct and serve HTTP responses in a custom web server.

    :attrs status_code (int): HTTP status code (e.g., 200, 404).
    :attrs headers (dict): dictionary of response headers.
    :attrs url (str): url of the response.
    :attrsencoding (str): encoding used for decoding response content.
    :attrs history (list): list of previous Response objects (for redirects).
    :attrs reason (str): textual reason for the status code (e.g., "OK", "Not Found").
    :attrs cookies (CaseInsensitiveDict): response cookies.
    :attrs elapsed (datetime.timedelta): time taken to complete the request.
    :attrs request (PreparedRequest): the original request object.

    Usage::

      #>>> import Response
      #>>> resp = Response()
      #>>> resp.build_response(req)
      #>>> resp
      <Response>
    """

    __attrs__ = [
        "_content",
        "_header",
        "status_code",
        "method",
        "headers",
        "url",
        "history",
        "encoding",
        "reason",
        "cookies",
        "elapsed",
        "request",
        "body",
        "reason",
    ]


    def __init__(self, request=None):
        """
        Initializes a new :class:`Response <Response>` object.

        : params request : The originating request object.
        """

        self._content = False
        self._content_consumed = False
        self._next = None

        #: Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        #: Case-insensitive Dictionary of Response Headers.
        #: For example, ``headers['content-type']`` will return the
        #: value of a ``'Content-Type'`` response header.
        self.headers = {}

        #: URL location of Response.
        self.url = None

        #: Encoding to decode with when accessing response text.
        self.encoding = None

        #: A list of :class:`Response <Response>` objects from
        #: the history of the Request.
        self.history = []

        #: Textual reason of responded HTTP Status, e.g. "Not Found" or "OK".
        self.reason = None

        #: A of Cookies the response headers.
        self.cookies = CaseInsensitiveDict()

        #: The amount of time elapsed between sending the request
        self.elapsed = datetime.timedelta(0)

        #: The :class:`PreparedRequest <PreparedRequest>` object to which this
        #: is a response.
        self.request = None

    #helper
    @staticmethod
    def ok_html(body_bytes):
        r = Response()
        r.status_code = 200;
        r.reason = "OK"
        r.headers["Content-Type"] = "text/html"
        r._content = body_bytes
        return r

    @staticmethod
    def ok_json(obj):
        import json
        r = Response()
        r.status_code = 200;
        r.reason = "OK"
        r.headers["Content-Type"] = "application/json"
        r._content = (obj if isinstance(obj, (bytes, bytearray)) else json.dumps(obj).encode())
        return r

    @staticmethod
    def unauthorized_html(msg="Unauthorized"):
        # 401
        r = Response()
        r.status_code = 401;
        r.reason = "Unauthorized"
        r.headers["Content-Type"] = "text/html"
        r._content = f"<h1>401 Unauthorized</h1><p>{msg}</p>".encode()
        return r

    @staticmethod
    def internal_server_error_html(msg="Internal Server Error"):
        # 500
        r = Response()
        r.status_code = 500;
        r.reason = "Internal Server Error"
        r.headers["Content-Type"] = "text/html"
        r._content = f"<h1>500 Internal Server Error</h1><p>{msg}</p>".encode()
        return r

    def set_cookie(self, name, value, extras="Path=/; HttpOnly"):
        #  allow setting cookies (supports multiple Set-Cookie)
        # moi line la mot header set-cookie:
        val = f"{name}={value}"
        if extras:
            val += f"; {extras}"
        if "Set-Cookie" in self.headers:
            prev = self.headers["Set-Cookie"]
            if isinstance(prev, list):
                prev.append(val)
            else:
                self.headers["Set-Cookie"] = [prev, val]
        else:
            self.headers["Set-Cookie"] = val

    def get_mime_type(self, path):
        """
        Determines the MIME type of a file based on its path.

        "params path (str): Path to the file.

        :rtype str: MIME type string (e.g., 'text/html', 'image/png').
        """

        try:
            mime_type, _ = mimetypes.guess_type(path)
        except Exception:
            return 'application/octet-stream'
        return mime_type or 'application/octet-stream'


    def prepare_content_type(self, mime_type='text/html'):
        """
        Prepares the Content-Type header and determines the base directory
        for serving the file based on its MIME type.

        :params mime_type (str): MIME type of the requested resource.

        :rtype str: Base directory path for locating the resource.

        :raises ValueError: If the MIME type is unsupported.
        """
        
        base_dir = ""

        # Processing mime_type based on main_type and sub_type
        main_type, sub_type = mime_type.split('/', 1)
        print("[Response] processing MIME main_type={} sub_type={}".format(main_type,sub_type))
        if main_type == 'text':
            self.headers['Content-Type']='text/{}'.format(sub_type)
            if sub_type == 'plain' or sub_type == 'css':
                base_dir = BASE_DIR+"static/"
            elif sub_type == 'html':
                base_dir = BASE_DIR+"www/"
            else:
                #handle_text_other(sub_type)
                print(f"[Response] Unsupported text sub_type: {sub_type}")
                raise ValueError("Invalid MEME type")
        elif main_type == 'image':
            base_dir = BASE_DIR+"static/"
            self.headers['Content-Type']='image/{}'.format(sub_type)
        elif main_type == 'application':
            base_dir = BASE_DIR+"apps/"
            self.headers['Content-Type']='application/{}'.format(sub_type)
        #
        #  TODO: process other mime_type
        #        application/xml       
        #        application/zip
        #        ...
        #        text/csv
        #        text/xml
        #        ...
        #        video/mp4 
        #        video/mpeg
        #        ...
        #
        else:
            raise ValueError("Invalid MEME type: main_type={} sub_type={}".format(main_type,sub_type))

        return base_dir


    def build_content(self, path, base_dir):
        """
        Loads the objects file from storage space.

        :params path (str): relative path to the file.
        :params base_dir (str): base directory where the file is located.

        :rtype tuple: (int, bytes) representing content length and content data.
        """

        filepath = os.path.join(base_dir, path.lstrip('/'))

        print("[Response] serving the object at location {}".format(filepath))
            #
            #  TODO: implement the step of fetch the object file
            #        store in the return value of content
            #
        # Neu khong co file thi return empty
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return 0, b""
        try:  # CHANGE: Add try-except for file read
            with open(filepath, "rb") as f:
                content = f.read()
            return len(content), content
        except Exception as e:
            print(f"[Response] Error reading file {filepath}: {e}")
            return 0, b""

    def serialize(self):
        """Serializes the complete HTTP response into bytes."""
        # Ensure status and reason are set, default if not
        if not self.status_code:
            self.status_code = 200
        if not self.reason:
            self.reason = "OK"

        status_line = f"HTTP/1.1 {self.status_code} {self.reason}\r\n"

        # Prepare headers
        header_lines = []

        # Set content length header if body exists and not already set
        if self._content is not False and 'Content-Length' not in self.headers:
            self.headers['Content-Length'] = str(len(self._content))

        # Add standard headers if not present
        if 'Date' not in self.headers:
            self.headers['Date'] = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        if 'Connection' not in self.headers:
            self.headers['Connection'] = 'close'

        # Format all headers
        for key, value in self.headers.items():
            # Vi set cookie co nhieu dong, nen ta append nhieu dong vao headerline thay vi gom chung
            if key.lower() == 'set-cookie' and isinstance(value, list):
                for cookie_val in value:
                    header_lines.append(f"Set-Cookie: {cookie_val}\r\n")
            else:
                header_lines.append(f"{key}: {value}\r\n")

        headers_str = "".join(header_lines) #Gom lai thanh moi chuoi duy nhat

        # Combine all parts thanh 1 byte duy nhat
        response_bytes = status_line.encode('utf-8')
        response_bytes += headers_str.encode('utf-8')
        response_bytes += b"\r\n"  # End of headers

        if self._content: #body
            response_bytes += self._content

        return response_bytes

    """ Thay bang serialize
    def build_response_header(self, request):
        
        Constructs the HTTP response headers based on the class:`Request <Request>
        and internal attributes.

        :params request (class:`Request <Request>`): incoming request object.

        :rtypes bytes: encoded HTTP response header.
        
        reqhdr = request.headers
        rsphdr = self.headers

        #Build dynamic headers
        headers = {
                "Accept": "{}".format(reqhdr.get("Accept", "application/json")),
                "Accept-Language": "{}".format(reqhdr.get("Accept-Language", "en-US,en;q=0.9")),
                "Authorization": "{}".format(reqhdr.get("Authorization", "Basic <credentials>")),
                "Cache-Control": "no-cache",
                "Content-Type": "{}".format(self.headers['Content-Type']),
                "Content-Length": "{}".format(len(self._content)),
#                "Cookie": "{}".format(reqhdr.get("Cookie", "sessionid=xyz789")), #dummy cooki
        #
        # TODO prepare the request authentication
        #

	# self.auth = ...
                "Date": "{}".format(datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")),
                "Max-Forward": "10",
                "Pragma": "no-cache",
                "Proxy-Authorization": "Basic dXNlcjpwYXNz",  # example base64
                "Warning": "199 Miscellaneous warning",
                "User-Agent": "{}".format(reqhdr.get("User-Agent", "Chrome/123.0.0.0")),
            }

        # Header text alignment
            #
            #  TODO: implement the header building to create formated
            #        header from the provied headers
            #
        #
        # TODO prepare the request authentication
        #
	# self.auth = ...
        return str(fmt_header).encode('utf-8')
    """

    """
    def build_notfound(self):
        
            Constructs a standard 404 Not Found HTTP response.
    
            :rtype bytes: Encoded 404 response.
            
    
            return (
                    "HTTP/1.1 404 Not Found\r\n"
                    "Accept-Ranges: bytes\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: 13\r\n"
                    "Cache-Control: max-age=86000\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "404 Not Found"
                ).encode('utf-8')
    """

    #ham nay chi thuc hien build thoi, serialize de sau
    def build_response(self, request):
        """
        Builds a full HTTP response including headers and content based on the request.

        :params request (class:`Request <Request>`): incoming request object.

        :rtype bytes: complete HTTP response using prepared headers and content.
        """

        path = request.path
        if not path:  # Path k dc parse thi tra ve loi 400
            self.status_code = 400
            self.reason = "Bad Request"
            self.headers['Content-Type'] = 'text/html'
            self._content = b"<h1>400 Bad Request</h1>"
            return self

        #mime la dictionary dang type/subtype nhu image/png
        mime_type = self.get_mime_type(path)
        print("[Response] {} path {} mime_type {}".format(request.method, request.path, mime_type))

        base_dir = ""
        c_len = 0

        #If HTML, parse and serve embedded objects
        try:
            if path.endswith('.html') or mime_type == 'text/html':
                base_dir = self.prepare_content_type(mime_type='text/html')
            elif mime_type == 'text/css':
                base_dir = self.prepare_content_type(mime_type='text/css')
            #
            # TODO: add support objects
            #
            else:
                # If mime type is not supported, then 404
                print(f"[Response] Unsupported MIME type: {mime_type}")
                base_dir = ""

        except ValueError as e:
            # prepare_content_type bao loi
            print(f"[Response] Error in prepare_content_type: {e}")
            base_dir = ""

        if not base_dir:
            c_len, self._content = 0, b""
        else:
            c_len, self._content = self.build_content(path, base_dir)

        if c_len == 0 and not self._content:  # Check for 0 length or empty content
            self.status_code = 404
            self.reason = "Not Found"
            self.headers['Content-Type'] = 'text/html'
            self._content = b"<h1>404 Not Found</h1>"
        else:
            self.status_code = 200
            self.reason = "OK"
            # Content-Type is already set by prepare_content_type
            self.headers['Content-Length'] = str(c_len)  # Set content length

        return self