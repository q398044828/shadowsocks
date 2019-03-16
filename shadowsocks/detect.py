#!/usr/bin/python
# coding=utf-8

#
#   根据审计规则，异步检查流量是否违规，违规的中断连接配置的时间长度
#

# yum install -y python-gevent

import logging
import common
import threading
import Queue
import time


class DetectThread(threading.Thread):
    dataQueue=None
    def __init__(self):
        threading.Thread.__init__(self)
        DetectThread.dataQueue=Queue.Queue()
        print ".......... detect thread init ..."

    #  异步审计
    #  将数据构造成类 添加到队列，新开线程处理
    @staticmethod
    def async_detect(data, remote_addr,remote_port,connect_type,relay):
        print '------------- add data '
        DetectThread.dataQueue.put(DetectData(data,remote_addr,remote_port,connect_type,relay))

    def run(self):
        print '--------------- detect thread run---'
        while True:
            time.sleep(5)
            # class DetectData
            data=DetectThread.dataQueue.get()

            self.detect(data)

        print '--------------- detect thread run complete---'

    def detect(self,detectData):
        print '--------------- detect thread handle data ---'
        data=detectData._data
        relay=detectData._relay
        remote_addr=detectData._remote_addr
        remote_port=detectData._remote_port
        connect_type=detectData._connect_type

        if not relay._server.is_pushing_detect_text_list:
            for id in relay._server.detect_text_list:
                if common.match_regex(
                        relay._server.detect_text_list[id]['regex'], str(data)):
                    print('-----------------------------')
                    if relay._config['is_multi_user'] != 0 \
                            and relay._current_user_id != 0:
                        if relay._server.is_cleaning_mu_detect_log_list == False \
                                and id not in relay._server.mu_detect_log_list[
                            relay._current_user_id]:
                            relay._server.mu_detect_log_list[
                                relay._current_user_id].append(id)
                    else:
                        if relay._server.is_cleaning_detect_log == False and id not in relay._server.detect_log_list:
                            relay._server.detect_log_list.append(id)
                    relay._handle_detect_rule_match(remote_port)


                    print (
                        'This connection match the regex: id:%d was reject,regex: %s ,%s connecting %s:%d from %s:%d via port %d' %
                        (relay._server.detect_text_list[id]['id'],
                         relay._server.detect_text_list[id]['regex'],
                         (connect_type == 0) and 'TCP' or 'UDP',
                         common.to_str(remote_addr),
                         remote_port,
                         relay._client_address[0],
                         relay._client_address[1],
                         relay._server._listen_port))


class DetectData(object):
    def __init__(self,data,remote_addr,remote_port,connect_type,relay):
        self._data=data
        self._relay=relay;
        self._remote_addr=remote_addr
        self._remote_port=remote_port
        self._connect_type=connect_type


def test():
    print '------------test-------------'
