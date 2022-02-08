import time
from zapv2 import ZAPv2
from app.config import ZAP_Config

# apiKey to currently running ZAP instance
apiKey = ZAP_Config.API_KEY
# ZAP client instance
zap=ZAPv2(apikey=apiKey)

# Crawl specified target with traditional spider and return identified resources
def crawl(target):

    # Opens a url forcing the proxies to be used
    zap.urlopen(target)
    time.sleep(2)
    print('Crawling target {}'.format(target))
    time.sleep(2)

    # ID for current scanning process, referenced to retrieve spider status and results
    scanID = zap.spider.scan(target)

    # Get spider status
    while int(zap.spider.status(scanID)) < 100:
        #loop until spider status reaches 100%
        time.sleep(1)

    print('Crawling completed!')
    # Retrieve spider results as list
    crawl_results = zap.spider.results(scanID)
    return crawl_results

# Apply Active Scan Rules to target, return identified alerts with riskID = 3 (omits low level risks)
def activeScan(target):

    print('Active Scanning target {}'.format(target))

    # ID for current scanning process, referenced to retrieve ascan status and results
    scanID = zap.ascan.scan(target)

    while int(zap.ascan.status(scanID)) < 100:
        # Loop until the  ascan status reaches 100%, print status in console
        print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
        time.sleep(5)

    print('Active Scan completed!')
    # Retrieve ascan results as list of dict
    active_scan_results = zap.core.alerts(baseurl=target, riskid=3)
    return active_scan_results







