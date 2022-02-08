from app import app
from flask import render_template, request
from app.forms import StartScanForm
from app.ZAP.ZAP_scan import crawl, activeScan
from app.ZAP.ZAP_filterResults import extractRelevantInfo, extractXSSAlerts
from app.config import ZAP_Config
from app.Jaeger.Jaeger_extract import getSpans, getTraces
from app.Pysa.Pysa_generateRules import extractSourcesSinks, readResults
import requests

# IAST Prototype dashboard
@app.route('/', methods=['GET', 'POST'])
def index() -> str:
    # Form in which the target application URL is specified
    form = StartScanForm()
    if request.method == 'POST' and form.validate_on_submit():
        print('### Starting IAST process ###')
        # Get the target application URL
        target = form.target.data
        print('--- Starting ZAP penetration testing ---')
        try:
            # Deploy ZAP's traditional spider onto the target application
            crawl_results = crawl(target)
            # Deploy ZAP's active scan rules onto the target application
            active_scan_results = activeScan(target)
            # Get the reflected and persistent XSS alerts of the active scan
            # results (see ZAP_Config)
            xss_alerts = extractXSSAlerts(active_scan_results,
                                          ZAP_Config.ALERT_FILTER_VALUES)
            # Get the 'name', 'url', 'method', 'param' and 'attack' data of
            # the list of reflected and persistent XSS alerts (see ZAP_Config)
            ZAP_report = extractRelevantInfo(ZAP_Config.KEY_FILTER_VALUES,
                                             xss_alerts)
            print('--- Starting extraction of traces ---')
            # For every alert within the list of relevant alert data:
            for alert in ZAP_report:
                url = alert["url"]
                method = alert["method"]
                attack = alert["attack"]
                # Query matching traces
                traces_dic = getTraces(url, method)
                # Get the corresponding span of the alert
                span = getSpans(traces_dic, attack)
                # Find the source and the sink of the span that lead to the alert
                extractSourcesSinks(span, attack)
            print('### IAST process terminated ###')
            # Retrieve the dynamically declared source and sink model for display
            # within the IAST dashboard
            Pysa_rules = readResults()
            success_msg = "Security rules have successfully been generated! " \
                          "You can now run Pysa!"
            # Return all results of the previous subprocesses
            return render_template('index.html',
                                   form=form, crawl_results=crawl_results,
                                   dast_results=ZAP_report, sast_results=Pysa_rules,
                                   success_msg=success_msg)
        # Catch possible errors
        except (requests.exceptions.ProxyError,
                requests.exceptions.ConnectionError,
                ValueError):
            if requests.exceptions.ProxyError:
                error = "Communication with ZAP failed! Make sure ZAP is running and that the API key is correctly specified in the configurations!"
            elif requests.exceptions.ConnectionError:
                error = "Communication with ZAP failed! Make sure Jaeger is running!"
            elif ValueError:
                error = "Communication with the target application failed. Make sure it is running!"
            return render_template('index.html',
                                   form=form, error=error)
    return render_template('index.html',
                           form=form)


