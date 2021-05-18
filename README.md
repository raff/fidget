# fidget
An HTTP(S) proxy that can fidget with your requests

fidget is an HTTP/HTTPS proxy that can log, modify or reject requests and responses.
It's similar in principle to [https://www.telerik.com/fiddler] but hopefully easier to use.
It has support for "sniffing" HTTPS requests by implementing man-in-the-middle interception,
if you install the proper CA in your browser.

fidget uses HCL as the configuration language and support the following parameters and filters:

Available configuration parameters
----------------------------------

port = [host]:port          // listening port
mitm = bool                 // enable HTTPS sniffing via MITM for all requests
verbose = bool              // log proxy details
logs = bool                 // log requests and responses
  
Available filters
-----------------
onConnect                   // executed before sending a CONNECT request to the host
onRequest                   // executed before sending the request
onResponse                  // executed before returning the response
  
Conditions
----------
Conditions are in the form conditionType: conditionValue, added to the "conditions" variable.
If there is no "conditions" variable, the filter is executed for all requests or responses.
If there are multiple conditions, they all have to match in order to satisfy the filter.
Conditions can also be negated by preceding them with "!" (i.e. "!hostIs":"example.com").

Common conditions (for onRequest and onResponse)
------------------------------------------------
hostIs: "host:port"            // if request host is "host:port"
hostMatches: "regexp"          // if request host matches regular expression
urlIs: "url"                   // if request URL (path, host/path) is "url"
urlMatches: "regexp"           // if request URL matches regular expression
urlHasPrefix: "prefix"         // if request URL (path, host/path) starts with prefix
methodIs: "method"             // if request method is "method"

Response conditions (only valid for onResponse)
-----------------------------------------------
statusIs: status               // HTTP response status code is status
contentTypeIs: contentType     // response content type is contentType

Available onConnect actions
---------------------------
action = "accept"              // continue CONNECT request
action = "reject"              // reject CONNECT request
action = "mitm"                // enable MITM for this connection (same as global `mitm`, but only for this connection)

Available onRequest actions
---------------------------
request {                     // modify incoming request, before sending
  setHeaders = {name: value, ...}
  addHeaders = {name: value, ...}
  delHeaders = [name, ...]
}

response {                    // create response (and abort request)
  status = statusCode
  body = "body"

  setHeaders = {name: value, ...}
  addHeaders = {name: value, ...}
  delHeaders = [name, ...]
}

Available onResponse actions
----------------------------
status = statusCode
body = "body"

setHeaders = {name: value, ...}
addHeaders = {name: value, ...}
delHeaders = [name, ...]


Example configuration file:
---------------------------

port=:8080              // list on port :8080
mitm=true               // enable sniffing HTTPS requests on all requests
                        // use onConnect { action = "mitm" } to selectively enable for certain hosts

onConnect {             // reject requests to https://bad.host.com/
  conditions = {hostIs: "bad.host.com:443"}
  action = "reject"
}

onRequest {             // for all incoming requests, add "X-Proxied-By"
    setHeaders = {"X-Proxied-By": "gogo-proxy"}
}

onResponse {            // for all outgoing responses, remove "X-Proxied-By"
    delHeaders = ["X-Proxied-By"]
}

onRequest {
    conditions = {hostIs: "teapot.example.com"}  // if request is for "teapot.example.com", return status 418 (I'm a teapot)
    response {
        status = 418
    }
}

onResponse {
    conditions = {statusIs: 418}  // if status is 418, replace body and content-type
    setHeaders = {"Content-Type", "text/teapot"}
    body = "short and stout"
}
