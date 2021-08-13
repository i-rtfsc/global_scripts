#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-


import datetime
import threading
import time

import requests
import schedule as schedule

url = 'http://api.huobi.br.com/market/history/kline?symbol={who}'


def runThreaded(job_func):
    job_thread = threading.Thread(target=job_func)
    job_thread.start()


def main():
    doge_usdt = requests.post(url.format(who='dogeusdt'))
    doge = doge_usdt.json()['data'][0]['close']
    shib_usdt = requests.post(url.format(who='shibusdt'))
    shib = shib_usdt.json()['data'][0]['close']
    sol_usdt = requests.post(url.format(who='solusdt'))
    sol = sol_usdt.json()['data'][0]['close']
    print(datetime.datetime.now(), ', doge =', doge, ', shib =', shib, ', sol =', sol)


schedule.every(1).minutes.do(runThreaded, main)

if __name__ == '__main__':
    try:
        main()
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        # User interrupt the program with ctrl+c
        exit()
