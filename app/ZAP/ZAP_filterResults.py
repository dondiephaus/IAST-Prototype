import json
from app.config import ZAP_Config
import datetime

# Filters list of dicts (dicList) to specified set of values (alerts)
# Returns list of dicts containing relevant xss-alerts
def extractXSSAlerts(dicList, alerts):

    # Loops through dicts and retrieves dicts that contain the specified values within the 'alert'-key
    xss_alerts = list(filter(lambda d: d['alert'] in alerts, dicList))

    return xss_alerts

# Filters list of dicts (dicList) to specified set of keys (keys)
# Returns a list of dicts that only contain the specified key-value pairs
def extractRelevantInfo(keys, dicList):

    # Loops through dicts and retrieves only entries that contain the specified key
    filtered_dicList = [dict((k, d[k]) for k in keys if k in d) for d in dicList]

    # Writes results to .json file with timestamp
    with open(ZAP_Config.OUTPUT_PATH +
              datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S') +
              '.json', 'a') as outputfile:
        json.dump(filtered_dicList, outputfile, indent=4)
        print('Active scan report has been filtered. Results are written to: ' +
              ZAP_Config.OUTPUT_PATH)

    return filtered_dicList

