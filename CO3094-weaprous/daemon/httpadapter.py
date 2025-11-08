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
daemon.httpadapter
~~~~~~~~~~~~~~~~~

This module provides a http adapter object to manage and persist 
http settings (headers, bodies). The adapter supports both
raw URL paths and RESTful route definitions, and integrates with
Request and Response objects to handle client-server communication.
"""

from .request import Request
from .response import Response
from .dictionary import CaseInsensitiveDict

class HttpAdapter:
    """
    A mutable :class:`HTTP adapter <HTTP adapter>` for managing client connections
    and routing requests.

    The `HttpAdapter` class encapsulates the logic for receiving HTTP requests,
    dispatching them to appropriate route handlers, and constructing responses.
    It supports RESTful routing via hooks and integrates with :class:`Request <Request>` 
    and :class:`Response <Response>` objects for full request lifecycle management.

    Attributes:
        ip (str): IP address of the client.
        port (int): Port number of the client.
        conn (socket): Active socket connection.
        connaddr (tuple): Address of the connected client.
        routes (dict): Mapping of route paths to handler functions.
        request (Request): Request object for parsing incoming data.
        response (Response): Response object for building and sending replies.
    """

    __attrs__ = [
        "ip",
        "port",
        "conn",
        "connaddr",
        "routes",
        "request",
        "response",
    ]

    def __init__(self, ip, port, conn, connaddr, routes):
        """
        Initialize a new HttpAdapter instance.

        :param ip (str): IP address of the client.
        :param port (int): Port number of the client.
        :param conn (socket): Active socket connection.
        :param connaddr (tuple): Address of the connected client.
        :param routes (dict): Mapping of route paths to handler functions.
        """

        #: IP address.
        self.ip = ip
        #: Port.
        self.port = port
        #: Connection
        self.conn = conn
        #: Conndection address
        self.connaddr = connaddr
        #: Routes
        self.routes = routes
        #: Request
        self.request = Request()
        #: Response
        self.response = Response()

    def handle_client(self, conn, addr, routes):
        """
        Handle an incoming client connection.

        This method reads the request from the socket, prepares the request object,
        invokes the appropriate route handler if available, builds the response,
        and sends it back to the client.

        :param conn (socket): The client socket connection.
        :param addr (tuple): The client's address.
        :param routes (dict): The route mapping for dispatching requests.
        """

        # Connection handler.
        self.conn = conn        
        # Connection address.
        self.connaddr = addr
        # Request handler
        req = self.request
        # Response handler
        resp = Response(request=req)

        # Handle the request
        msg = ""
        try:
            raw_request = b""
            while b"\r\n\r\n" not in raw_request:
                chunk = conn.recv(1024)
                if not chunk:
                    # Client disconnected before sending full headers
                    print(f"[HttpAdapter] Client {addr} disconnected before sending headers.")
                    conn.close()
                    return
                raw_request += chunk

            # Split headers from the body (or body-part)
            header_part_raw, body_part_raw = raw_request.split(b"\r\n\r\n", 1)
            header_part_str = header_part_raw.decode('utf-8')

            # Find Content-Length to read the rest of the body
            content_length = 0
            for line in header_part_str.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        print(f"[HttpAdapter] Invalid Content-Length from {addr}.")
                        content_length = 0
                    break

            # Read exactly the amount of body specified
            while len(body_part_raw) < content_length:
                bytes_to_read = min(1024, content_length - len(body_part_raw))
                chunk = conn.recv(bytes_to_read)
                if not chunk:
                    print(f"[HttpAdapter] Client {addr} disconnected mid-body.")
                    conn.close()
                    return
                body_part_raw += chunk

            # Now, re-combine everything into the single string that req.prepare expects.
            # This is flawed (decoding a binary body) but required by req.prepare's design.
            try:
                body_part_str = body_part_raw.decode('utf-8')
            except UnicodeDecodeError:
                print("[HttpAdapter] Warning: Body is not valid UTF-8. Treating as raw.")
                # This will likely fail in req.prepare, but we try anyway.
                body_part_str = body_part_raw.decode('latin-1')

            msg = header_part_str + "\r\n\r\n" + body_part_str

            if not msg:
                print(f"[HttpAdapter] Empty request from {addr}. Closing.")
                conn.close()
                return
        except Exception as e:
            print(f"[HttpAdapter] Error receiving data: {e}")
            conn.close()
            return

        req.prepare(msg, routes)

        # Handle request hook
        if req.hook:
            print("[HttpAdapter] hook in route-path METHOD {} PATH {}".format(req.hook._route_path,req.hook._route_methods))
            req.hook(req)
            #
            # TODO: handle for App hook here
            #
            try:
                # The hook function takes the request and returns a Response object
                resp_from_hook = req.hook(req)

                # Check if the hook returned a valid Response
                if isinstance(resp_from_hook, Response):
                    resp = resp_from_hook
                else:
                    # Hook didn't return a Response, create an error
                    print(f"[HttpAdapter] Hook for {req.path} did not return a Response object.")
                    resp = Response.internal_server_error_html("Hook did not return a valid response.")

            except Exception as e:
                print(f"[HttpAdapter] Hook failed: {e}")
                import traceback
                traceback.print_exc() #debug
                resp = Response.internal_server_error_html(str(e))
        else:
            # Build file-based response (this method now returns `self`)
            print(f"[HttpAdapter] No hook found. Serving file for path: {req.path}")
            resp.build_response(req)

        # Build response
        response_bytes = resp.serialize()

        #print(response)
        conn.sendall(response_bytes)
        conn.close()

    @property
    def extract_cookies(self, req, resp):
        """
        Build cookies from the :class:`Request <Request>` headers.

        :param req:(Request) The :class:`Request <Request>` object.
        :param resp: (Response) The res:class:`Response <Response>` object.
        :rtype: cookies - A dictionary of cookie key-value pairs.
        """
        cookies = {}
        # Vì cookie đã được build sẵn trong request rồi, nên ta chỉ cần extract từ req
        return req.cookies

    def build_response(self, req, resp): #Có vẻ dư vì respone có func này mà nhỉ?
        """Builds a :class:`Response <Response>` object 

        :param req: The :class:`Request <Request>` used to generate the response.
        :param resp: The  response object.
        :rtype: Response
        """
        response = Response()

        # Set encoding.
        #response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode("utf-8")
        else:
            response.url = req.url

        # Add new cookies from the server.
        #response.cookies = extract_cookies(req)
        response.cookies = req.cookies #Lấy cookie từ request bỏ vào response

        # Give the Response some context.
        response.request = req
        response.connection = self

        return response

    # def get_connection(self, url, proxies=None):
        # """Returns a url connection for the given URL. 

        # :param url: The URL to connect to.
        # :param proxies: (optional) A Requests-style dictionary of proxies used on this request.
        # :rtype: int
        # """

        # proxy = select_proxy(url, proxies)

        # if proxy:
            # proxy = prepend_scheme_if_needed(proxy, "http")
            # proxy_url = parse_url(proxy)
            # if not proxy_url.host:
                # raise InvalidProxyURL(
                    # "Please check proxy URL. It is malformed "
                    # "and could be missing the host."
                # )
            # proxy_manager = self.proxy_manager_for(proxy)
            # conn = proxy_manager.connection_from_url(url)
        # else:
            # # Only scheme should be lower case
            # parsed = urlparse(url)
            # url = parsed.geturl()
            # conn = self.poolmanager.connection_from_url(url)

        # return conn


    def add_headers(self, request):
        """
        Add headers to the request.

        This method is intended to be overridden by subclasses to inject
        custom headers. It does nothing by default.

        
        :param request: :class:`Request <Request>` to add headers to.
        """
        pass

    def build_proxy_headers(self, proxy):
        """Returns a dictionary of the headers to add to any request sent
        through a proxy. 

        :class:`HttpAdapter <HttpAdapter>`.

        :param proxy: The url of the proxy being used for this request.
        :rtype: dict
        """
        headers = {}
        #
        # TODO: build your authentication here
        #       username, password =...
        # we provide dummy auth here
        #
        username, password = ("user1", "password")

        if username:
            #headers["Proxy-Authorization"] = (username, password)
            #basic auth có dạng :<auth-scheme> <credentials>
            import base64
            creds = f"{username}:{password}".encode()
            headers["Proxy-Authorization"] = f"Basic {base64.b64encode(creds).decode()}"

        return headers