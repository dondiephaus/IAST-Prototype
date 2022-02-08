# General configurations for the iast-prototype project
class Config(object):
    PORT = '5000'
    DEBUG = True
    SECRET_KEY = 'iast-prot-ba2021'

# Configurations for the ZAP API and filtering operations
class ZAP_Config(object):
    API_KEY = 'o5pvb0qplf7a98175ct2k0oqqb'
    ALERT_FILTER_VALUES = ['Cross Site Scripting (Reflected)',
                           'Cross Site Scripting (Persistent)']
    KEY_FILTER_VALUES = ['name', 'url', 'method', 'param', 'attack']
    OUTPUT_PATH = 'app/output/ZAP_report'

# Configurations for the Jaeger API and filtering operations
class Jaeger_Config(object):
    JSON_API = 'http://localhost:16686/api/traces?'
    SERVICE = 'FlaskXSS'
    LIMIT_TRACES = 1000
    OUTPUT_PATH = 'app/output/Jaeger_traces'

# Configurations for the generation of Pysa security rules
class Pyre_Config(object):
    XSS_SOURCE_RULE = 'TaintSource[UserControlled]'
    XSS_SINK_RULE = 'TaintSink[XSS]'
    PYSA_FILE_DIR = 'app/Pysa/sources_sinks.pysa'

