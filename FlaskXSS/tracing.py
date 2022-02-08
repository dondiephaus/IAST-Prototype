from jaeger_client import Config
import logging

# Initialize global tracer instance (Jaeger)
def init_tracer(service):
    logging.getLogger('').handlers = []
    logging.basicConfig(format='%(message)s', level=logging.DEBUG)

    config = Config(
        config={
            'sampler': {
                'type': 'const',
                'param': 1,
            },
            'logging': True,
            'reporter_batch_size': 1,
        },
        service_name=service,
    )

    # Sets global open-tracing.tracer variable
    return config.initialize_tracer()


# Sets span-tags for a request's url and its method, adds it to a given span
def trace_request_url_method(request, span):
    span.set_tag('url', request.url)
    span.set_tag('method', request.method)