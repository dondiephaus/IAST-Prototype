import html
from flask import Flask, request, make_response, render_template_string, render_template
import db
from tracing import init_tracer, trace_request_url_method

# Initialize instance of Flask app
app = Flask(__name__)
# Initialize tracer to service "FlaskXSS"
tracer = init_tracer('FlaskXSS')

"""
Rules of tracing instrumentation:
    1. Any dynamically retrieved or set data objects and their related operations are traced 
    within a key-value tag (Data objects can be function return values or class attributes)
        1.1 Data objects originating from an operation that obtains data externally 
        are labeled with the 'OUT' direction decorator
        1.2 Data objects that are passed as a function argument are labeled 
        with the 'IN' direction decorator
    2. Tags are composed of:
        2.1 tag-key: [directional decorator] + '::' + [fully qualified name of an operation]
        2.2 tag-value: 
            2.2.1 IN operation: [name of the function argument] + '::' + [value of the data object]
            2.2.2 OUT operation: [value of the data object] 

This logic can be derived from the follow pseudocode listing:
def generate_tag(data, operation, span):
    if Data_derived == True:
        Direction_tag = 'OUT:: '
    elif Data_passed_to_function == True:
        Direction_tag = 'IN:: '
        Name_of_function_argument = str(get_function_argument(operation, data) + '::')

    fully_qualified_name = str(get_fully_qualified_name(operation))
    
    key = Direction_tag + fully_qualified_name
    if Name_of_function_argument:
        value = Name_of_function_argument + str(data)
    else:
        value= str(data)

    span.set_tag(key, value)
"""

# FlaskXSS homepage, contains no vulnerabilities
@app.route('/', methods=['GET'])
def index():
        # No dynamic data objects are related to this handler function, thus no span is started
        return render_template('index.html')


# Persistent XSS Demo: Receives comment string, adds it to database, returns template with all comments
@app.route('/persistent', methods=['POST', 'GET'])
def persistent() -> str:

    # start new span "/persistent" to identify the called handler function
    with tracer.start_span('/persistent') as span:

        # add tags containing the request's method and url to the span
        trace_request_url_method(request, span)

        if request.method == 'POST':

            # Data object is externally derived from a class attribute (OUT)
            # span.set_tag(directional decorator::fully qualified name, str(value of the data object))
            span.set_tag('OUT::werkzeug.wrappers.BaseRequest.form', str(request.form['comment']))
            comment = request.form['comment']

            # Data object is passed as a function argument (IN)
            # span.set_tag(directional decorator::fully qualified name,
            #              name of the function argument::str(value of the data object))
            span.set_tag('IN::def db.add_comment(comment)', ('comment::' + str(comment)))
            db.add_comment(comment)

        # Data object is externally derived from a class attribute (OUT)
        span.set_tag('OUT::def db.get_comments(search_query)', str(db.get_comments()))
        comments = db.get_comments()

        # Data object is passed as a function argument (IN)
        span.set_tag('IN::def flask.templating.render_template(template_name_or_list, **context)',
                     ('**context::' + str(comments)))
        return render_template('persistent.html', comments=comments)


# Reflected XSS Demo: Receives query string, searches db, returns matching comment
@app.route('/reflected', methods=['GET'])
def reflected() -> str:

    # start new span "/reflected" to identify the called handler function
    with tracer.start_span('/reflected') as span:

        # add tags containing the request's method and url to the span
        trace_request_url_method(request, span)

        # Data object is externally derived from a class attribute (OUT)
        span.set_tag('OUT::werkzeug.wrappers.BaseRequest.args', str(request.args.get('query')))
        search_query = request.args.get('query')

        # Data object is externally derived from a class attribute (OUT)
        span.set_tag('OUT::def db.get_comments(search_query)', str(db.get_comments(search_query)))
        comments = db.get_comments(search_query)

        # Data object is passed as a function argument (IN)
        span.set_tag('IN::def flask.templating.render_template(template_name_or_list, **context)',
                     ('**context::' + str(comments)))
        # Data object is passed as a function argument (IN)
        span.set_tag('IN::def flask.templating.render_template(template_name_or_list, **context)',
                     ('**context::' + str(search_query)))
        return render_template('reflected.html', comments=comments, search_query=search_query)


# receives input from URL, returns it, script-tags are detected. ZAP cant detect this vulnerability
@app.route('/insufsanitize', methods=['GET'])
def insufsanitize() -> str:

    # start new span "/insufsanitize" to identify the called handler function
    with tracer.start_span('/insufsanitize') as span:

        # add tags containing the request's method and url to the span
        trace_request_url_method(request, span)

        # Data object is externally derived from a class attribute (OUT)
        span.set_tag('OUT::werkzeug.wrappers.BaseRequest.args', str(request.args.get('q')))
        input = request.args.get('q')

        if not input:
            # No dynamic data object related to this operation
            response = "No input!"
        elif "<script>" in input:
            # No dynamic data object related to this operation
            response = "Attack detected!"
        elif "alert" in input:
            # No dynamic data object related to this operation
            response = "Attack detected!"
        else:
            # No operation that could be added to tag
            response = "Input: " + input

        # Data object is passed as a function argument (IN)
        span.set_tag('IN::def flask.templating.render_template(template_name_or_list, **context)',
                     ('**context::' + str(response)))
        return render_template('sanitize.html', response=response)


# Receives input from URL, escapes it, returns it
@app.route('/sufsanitize', methods=['GET'])
def sufsanitize() -> str:

    # start new span "/sufsanitize" to identify the called handler function
    with tracer.start_span('/sufsanitize') as span:

        # add tags containing the request's method and url to the span
        trace_request_url_method(request, span)

        # Data object is externally derived from a class attribute (OUT)
        span.set_tag('OUT::werkzeug.wrappers.BaseRequest.args', str(request.args.get('q')))
        input = request.args.get('q')

        if not input:
            # No dynamic data object related to this operation
            response = "No input!"
        else:
            # Data object is passed as a function argument (IN)
            span.set_tag('IN::def html.escape(s, quote)', ('s::' + str((input))))
            # No operation that could be added to tag
            response = "Input: " + html.escape(input)

        # Data object is passed as a function argument (IN)
        span.set_tag('IN::def flask.templating.render_template_string(source, **context)',
                     str('source::' + response))
        return render_template_string(response)


# Returns Referer from HTTP header
@app.route('/xssheader', methods=['GET'])
def xssheader() -> str:

    # start new span "/xssheader" to identify the called handler function
    with tracer.start_span('/xssheader') as span:

        # add tags containing the request's method and url to the span
        trace_request_url_method(request, span)

        # Data object is externally derived from a class attribute (OUT)
        span.set_tag('OUT::werkzeug.wrappers.BaseRequest.headers', str(request.headers.get('Referer')))
        referer_header = request.headers.get('Referer')

        if not referer_header:

            # No dynamic data object related to this operation
            referer_header = "No Referer!"

        response = referer_header

        # Data object is passed as a function argument (IN)
        span.set_tag('IN::def flask.helpers.make_response(*args)', str('*args::' + response))
        return make_response(response)


if __name__ == '__main__':
    app.run(host='localhost', port='5001', debug=True)

"""
FLASKXSS IS BASED ON: https://github.com/bgres/xss-demo
"""
