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
import traceback
from flashtext.keyword import KeywordProcessor


class DetectThread(threading.Thread):
    # ----------- config --------------------
    detect_interval = 60  # 审查间隔  单位s
    # ----------- code ---------------------
    dataQueue = None
    timer = {}  # key放用户id,value放上次审查的时间
    keywork_update_timer = time.time()
    detect_text_list=None
    keyword_processor = KeywordProcessor()

    def __init__(self):
        threading.Thread.__init__(self)
        DetectThread.dataQueue = Queue.Queue()
        DetectThread.detect_interval = self.detect_interval
        DetectThread.keywork_update_timer = time.time()
        logging.info(".......... detect thread init ...")

    # 每分钟/秒抽查每个用户的数据1次，减少cpu消耗，审计规则7000条正则，太消耗cpu了
    @staticmethod
    def detect_judge(uid):
        try:
            # 如果第一次，则直接返回true标记要审查
            if not DetectThread.timer.has_key(uid):
                DetectThread.timer[uid] = time.time()  # 返回秒时间戳
                return True

            # 距离上次的检查距离大于配置时间时，返回true表示要审查，否则返回false表示不审查
            now = time.time()
            if (now - DetectThread.timer[uid]) > DetectThread.detect_interval:
                DetectThread.timer[uid] = now
                return True
            else:
                return False
        except Exception as e:
            traceback.print_exc()
            pass

    # 定时更新审查规则判断
    @staticmethod
    def detect_keyword_judge():
        try:
            now = time.time()
            if (now - DetectThread.keywork_update_timer) > DetectThread.detect_interval:
                DetectThread.keywork_update_timer = now
                return True
            else:
                return False
        except Exception as e:
            traceback.print_exc()
            pass

    #  异步审计
    #  将数据构造成类 添加到队列，新开线程处理
    @staticmethod
    def async_tcp_detect(data, uid, remote_addr, remote_port, connect_type, tcprelay):
        if DetectThread.detect_judge(uid):
            logging.info('-------------detect add tcp data ')
            DetectThread.dataQueue.put(DetectData().tcp(data, remote_addr, remote_port, connect_type, tcprelay))
            if DetectThread.detect_keyword_judge():
                DetectThread.detect_text_list_update(tcprelay.detect_text_list)

    @staticmethod
    def async_udp_detect(data, uid, server_addr, server_port, r_addr, udprelay):
        if DetectThread.detect_judge(uid):
            logging.info('------------- detect add udp data ')
            DetectThread.dataQueue.put(DetectData().udp(data, uid, server_addr, server_port, r_addr, udprelay))
            if DetectThread.detect_keyword_judge():
                DetectThread.detect_text_list_update(udprelay.detect_text_list)

    def run(self):
        logging.debug('--------------- keywork_rule loop update ')
        threading.Thread(target=self.keyword_rule())

        logging.debug('--------------- detect thread run---')
        while True:
            # class DetectData
            data = DetectThread.dataQueue.get()
            self.detect(data)

    @staticmethod
    def detect_text_list_update(detect_text_list):
        DetectThread.detect_text_list=detect_text_list

    # flashtext规则生成
    @staticmethod
    def keyword_update(detect_text_list):
        keyworkProcessor=KeywordProcessor()

        for id in detect_text_list:
            keyworkProcessor.add_keyword(detect_text_list[id]['regex'])

        DetectThread.keyword_processor=keyworkProcessor


    def detect(self, detectData):
        if 'tcp' == detectData._type:
            self.tcp_detect(detectData)
        else:
            self.udp_detect(detectData)

    def udp_detect(self, detectData):

        data = detectData._data
        relay = detectData._relay
        uid = detectData._uid
        server_addr = detectData._server_addr
        server_port = detectData._server_port
        r_addr = detectData._r_addr

        if not relay.is_pushing_detect_text_list:
            for id in relay.detect_text_list:
                if common.match_regex(
                        relay.detect_text_list[id]['regex'],
                        str(data)):
                    if relay._config['is_multi_user'] != 0 and uid != 0:
                        if relay.is_cleaning_mu_detect_log_list == False and id not in relay.mu_detect_log_list[
                            uid]:
                            relay.mu_detect_log_list[uid].append(id)
                    else:
                        if relay.is_cleaning_detect_log == False and id not in relay.detect_log_list:
                            relay.detect_log_list.append(id)
                    raise Exception(
                        'This connection match the regex: id:%d was reject,regex: %s ,connecting %s:%d from %s:%d via port %d' %
                        (relay.detect_text_list[id]['id'],
                         relay.detect_text_list[id]['regex'],
                         common.to_str(server_addr),
                         server_port,
                         r_addr[0],
                         r_addr[1],
                         relay._listen_port))

    def tcp_detect(self, detectData):

        data = detectData._data
        relay = detectData._relay
        remote_addr = detectData._remote_addr
        remote_port = detectData._remote_port
        connect_type = detectData._connect_type

        logging.debug('--------------- detect thread handle tcp data ---')

        if not relay._server.is_pushing_detect_text_list:
            for id in relay._server.detect_text_list:
                # pass
                if common.match_regex(
                        relay._server.detect_text_list[id]['regex'], str(data)):
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
    def __init__(self):
        object.__init__(self)

    def tcp(self, data, remote_addr, remote_port, connect_type, tcprelay):
        self._data = data
        self._relay = tcprelay
        self._remote_addr = remote_addr
        self._remote_port = remote_port
        self._connect_type = connect_type
        self._type = 'tcp'
        return self

    def udp(self, data, uid, server_addr, server_port, r_addr, udprelay):
        self._data = data
        self._relay = udprelay
        self._uid = uid
        self._server_addr = server_addr
        self._server_port = server_port
        self._r_addr = r_addr
        self._type = 'udp'
        return self


def test():
    print '------------test-------------'
