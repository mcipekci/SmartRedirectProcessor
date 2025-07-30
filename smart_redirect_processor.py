# Burp Suite Extension: Smart Redirect Processor
#
# This extension intelligently handles a specific server misconfiguration where a 3xx redirect
# response incorrectly contains the full, GZIP-compressed content of the target page.
#
# When it detects this specific case, it performs the following actions:
# 1. Changes the 3xx redirect status code to a 200 OK.
# 2. Removes any "Object moved" HTML from the response body.
# 3. Finds and decompresses the GZIP data embedded in the response body if the content is JavaScript.
# 4. Removes the incorrect 'Content-Encoding' header.
# 5. Serves the clean, decompressed content to the browser.
# 6. Adds a 'cyan' highlight and a descriptive comment to the request in the Proxy history.
# 7. Issues a pop-up alert and an entry in the Dashboard event log with the modified URL.

from burp import IBurpExtender, IHttpListener
import gzip
import io
import re

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        """
        This method is called by Burp when the extension is loaded.
        It registers the extension as an HTTP listener.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Smart Redirect Processor")
        callbacks.registerHttpListener(self)
        print("Smart Redirect Processor extension loaded.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        This method is called for each HTTP message processed by Burp.
        We are only interested in responses passing through the Proxy.
        """
        # Only process responses
        if not messageIsRequest and toolFlag == self._callbacks.TOOL_PROXY:
            
            # --- Get original response components ---
            original_response_bytes = messageInfo.getResponse()
            response_info = self._helpers.analyzeResponse(original_response_bytes)
            original_headers = response_info.getHeaders()
            original_body_array = original_response_bytes[response_info.getBodyOffset():]
            original_body_bytes = original_body_array.tostring()

            # --- Prepare for potential modifications ---
            new_headers = list(original_headers) # Create a mutable copy
            new_body = original_body_bytes       # Start with the original body
            modified = False                     # Flag to track if we need to build a new response

            # --- Main Logic Block: Check for large-bodied redirects ---
            if new_headers:
                status_line = new_headers[0]
                parts = status_line.split(' ', 2)
                
                # Condition: Is it a 3xx redirect with a body > 1KB?
                if len(parts) > 1 and parts[1].startswith('3') and len(new_body) > 1000:
                    
                    # --- This is the specific case we want to handle ---
                    modified = True # We will be modifying the response.
                    
                    # Action 1: Change status to 200 OK
                    new_status_line = re.sub(r' 3\d{2} .+', ' 200 OK', status_line, 1)
                    new_headers[0] = new_status_line
                    print("Status changed: {} -> 200 OK (body size > 1KB).".format(status_line.strip()))

                    # Action 2: Remove the "Object moved" HTML block
                    html_redirect_regex = re.compile(b'(?s)<html><head><title>Object moved</title></head><body>.*?</body></html>')
                    if html_redirect_regex.search(new_body):
                        new_body = html_redirect_regex.sub(b'', new_body, 1)
                        print("Removed 'Object moved' redirect HTML from body.")

                    # Action 3: If it's JavaScript, decompress the remaining GZIP content
                    is_js_target = False
                    for header in new_headers:
                        if header.lower().startswith("content-type:") and "application/x-javascript" in header.lower():
                            is_js_target = True
                            break
                    
                    if is_js_target:
                        GZIP_MAGIC_NUMBER = b'\x1f\x8b'
                        # Use the already cleaned 'new_body' for GZIP detection
                        start_index = new_body.find(GZIP_MAGIC_NUMBER)
                        
                        if start_index != -1:
                            print("Found GZIP data at offset {}, decompressing...".format(start_index))
                            gzipped_data_bytes = new_body[start_index:]
                            
                            try:
                                compressed_file = io.BytesIO(gzipped_data_bytes)
                                gzip_file = gzip.GzipFile(fileobj=compressed_file)
                                decompressed_body = gzip_file.read()
                                gzip_file.close()

                                # Update body and headers for the decompressed content
                                new_body = decompressed_body
                                new_headers = [h for h in new_headers if not h.lower().startswith("content-encoding:")]
                                print("Response successfully carved and decompressed.")
                            except IOError as e:
                                # If decompression fails, we revert the 'modified' flag
                                # so we don't send a corrupted response.
                                modified = False
                                print("GZIP decompression failed: {}".format(e))
            
            # --- If any modifications were made, build the new response and set notifications ---
            if modified:
                # Build the new response from the modified headers and body
                new_response = self._helpers.buildHttpMessage(new_headers, new_body)
                # Set the new response on the messageInfo object
                messageInfo.setResponse(new_response)

                # Get the request URL for more detailed notifications
                request_info = self._helpers.analyzeRequest(messageInfo)
                url = request_info.getUrl()

                # Add a highlight and comment to the Proxy history item
                messageInfo.setHighlight("cyan")
                messageInfo.setComment("Redirect modified and decompressed for URL: {}".format(url.toString()))
                
                # Create a pop-up alert and an entry in the main Dashboard event log
                alert_message = "Modified response for URL: {}".format(url.toString())
                self._callbacks.issueAlert(alert_message)
