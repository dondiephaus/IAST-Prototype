import requests, json
from urllib.parse import unquote, urlparse
from pathlib import PurePosixPath
import datetime
from app.config import Jaeger_Config

# Retrieves all traces matching with given request-method (POST/GET) and the route of a URL
# An unofficial HTTP JSON API specification can be found here: "https://github.com/jaegertracing/jaeger/issues/456"
# Returns list of dicts containing traces.
def getTraces(url, method):

    # Jaeger trace retrieval HTTP JSON API base url
    base = Jaeger_Config.JSON_API
    # Name of the target service
    service = 'service=' + Jaeger_Config.SERVICE
    # Maximum number of traces retrieved from the Jaeger collector
    limit = 'limit=' + str(Jaeger_Config.LIMIT_TRACES)
    # Extracts the HTTP handler function name from URL (Extracts String between first "/" and "?"
    operation = 'operation=/' + PurePosixPath(unquote(urlparse(url).path)).parts[1]
    # Request Method of the traces' request
    method = 'tags={"method"%3A"' + method + '"}'

    # Create a request url based on the declared variables above
    # Example: "http://localhost:16686/api/traces?service=FlaskXSS&limit=1000&operation=/xssheader&tags={"method"%3A"GET"}"
    request_url = str(base + '&'.join([service, limit, operation, method]))
    print('Retrieving data from: ' + request_url)
    # Send request
    request = requests.get(request_url, verify=False)
    # Parse response (JSON) to Python object (list of dicts)
    request_parsed = json.loads(request.text)

    return request_parsed


# Retrieves all spans matching a specified attack payload string (attack) from a dictionary
# Returns list of dicts.
def getSpans(lisdic, attack):

    # Declares empty list
    span_out = []

    # Loops through all:
    # -> Dicts containing all traces collected by Jaeger
    for trace in lisdic["data"]:
        # -> Traces containing all spans
        for span in trace["spans"]:
            # -> Tags
            for tag in span["tags"]:
                # If a tag within a span contains the attack payload:
                if tag["value"] == attack:
                    # Add the span to the list span_out
                    span_out = span["tags"]
                    # Stop the loop to prevent data pollution: one span is sufficient
                    break

    # Writes results to .json file with timestamp
    with open(Jaeger_Config.OUTPUT_PATH +
              datetime.datetime.now().strftime('%Y_%m_%d_%H_%M') +
              '.json', 'a') as outputfile:
        outputfile.write(json.dumps(span_out, indent=4) + ',')
        print('Spans have been filtered according to ZAP attack payload. Results are written to: ' +
              Jaeger_Config.OUTPUT_PATH)

    return span_out


