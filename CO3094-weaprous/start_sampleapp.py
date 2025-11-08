#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the "MIT License Agreement". Please see the LICENSE
# file that should have been included as part of this package.
#
# WeApRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#


"""
start_sampleapp
~~~~~~~~~~~~~~~~~

This module provides a sample RESTful web application using the WeApRous framework.

It defines basic route handlers and launches a TCP-based backend server to serve
HTTP requests. The application includes a login endpoint and a greeting endpoint,
and can be configured via command-line arguments.
"""

import json
import socket
import argparse
import os

from daemon.weaprous import WeApRous
from daemon.response import Response

PORT = 8000  # Default port

app = WeApRous()

#Task 1A: Authentication handling
@app.route('/login', methods=['POST'])
def login(request):
    """
    Handle user login via POST request.

    This route simulates a login process and prints the provided headers and body
    to the console.
    """

    print("[SampleApp] /login POST received.")

    # check if the credentials are in the raw body
    body_str = request.body.decode()
    is_valid = "admin" in body_str and "password" in body_str

    if is_valid:
        print("[SampleApp] Login successful for admin.")

        # Respond with the index page and set the cookie
        try:
            with open("www/index.html", "rb") as f:
                index_content = f.read()

            resp = Response.ok_html(index_content)
            # Set the cookie as per Task 1A
            resp.set_cookie("auth", "true", extras="Path=/")
            return resp

        except FileNotFoundError:
            print("[SampleApp] ERROR: www/index.html not found.")
            return Response.internal_server_error_html("Missing index.html")

    else:
        print("[SampleApp] Login failed.")
        # Invalid credentials, respond with 401
        return Response.unauthorized_html("Invalid username or password")


@app.route('/login', methods=['GET'])
def get_login_page(request):
    """
    Handle user login via GET request.
    Serves the login.html page.
    :param request (Request): The incoming request object.
    """
    print("[SampleApp] /login GET received, serving login.html")
    try:
        # Assumes 'www/login.html' exists
        with open("www/login.html", "rb") as f:
            login_content = f.read()
        return Response.ok_html(login_content)

    except FileNotFoundError:
        print("[SampleApp] ERROR: www/login.html not found.")
        return Response.internal_server_error_html("Missing login.html")

@app.route('/hello', methods=['PUT'])
def hello(headers, body):
    """
    Handle greeting via PUT request.

    This route prints a greeting message to the console using the provided headers
    and body.

    :param headers (str): The request headers or user identifier.
    :param body (str): The request body or message payload.
    """
    print("[SampleApp] ['PUT'] Hello in {} to {}".format(headers, body))


#Task 1B - cookies
@app.route('/', methods=['GET'])
@app.route('/index.html', methods=['GET'])
def get_index(request):
    """
    Handle greeting via GET request.

    :param request (Request): The incoming request object.
    """
    print("[SampleApp] / or /index.html GET received.")

    # Check for the cookie as per Task 1B
    if request.cookies.get("auth") == "true":
        print("[SampleApp] 'auth=true' cookie found. Serving page.")

        # Cookie is present, serve the index page
        try:
            with open("www/index.html", "rb") as f:
                index_content = f.read()
            return Response.ok_html(index_content)

        except FileNotFoundError:
            print("[SampleApp] ERROR: www/index.html not found.")
            return Response.internal_server_error_html("Missing index.html")
    else:
        print("[SampleApp] No 'auth=true' cookie. Returning 401.")
        # Cookie is missing or incorrect, respond with 401
        return Response.unauthorized_html(
            "<h1>401 Unauthorized</h1><p>You must log in to view this page.</p>"
            # --- CHANGE: Make this link clickable ---
            '<p>Please <a href="/login">go to the login page</a>.</p>'
        )


if __name__ == "__main__":
    # Parse command-line arguments to configure server IP and port
    parser = argparse.ArgumentParser(prog='Backend', description='', epilog='Beckend daemon')
    parser.add_argument('--server-ip', default='0.0.0.0')
    parser.add_argument('--server-port', type=int, default=PORT)
 
    args = parser.parse_args()
    ip = args.server_ip
    port = args.server_port

    # Prepare and launch the RESTful application
    app.prepare_address(ip, port)
    app.run()