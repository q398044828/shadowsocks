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


class DetectThread(threading.Thread):
    def __init__(self, server):
        self._server = server
        self._dataQueue=Queue()
        print ".......... detect handler init ..."

    #  异步审计
    #  将数据构造成类 添加到队列，新开线程处理
    def async_detect(self, data, remote_addr, remote_port, connect_type):
        self._dataQuueue.put(DetectData(data,remote_addr,remote_port,connect_type))

    def run(self):
        while not self._dataQueue.empty():
            # class DetectData
            data=self._dataQueue.get()
            self.detect(data)


    def detect(self,detectData):
        data=detectData._data
        remote_addr=detectData._remote_addr
        remote_port=detectData._remote_port
        connect_type=detectData._connect_type

        if not self._server.is_pushing_detect_text_list:
            for id in self._server.detect_text_list:
                if common.match_regex(
                        self._server.detect_text_list[id]['regex'], str(data)):
                    if self._config['is_multi_user'] != 0 \
                            and self._current_user_id != 0:
                        if self._server.is_cleaning_mu_detect_log_list == False and id not in \
                                self._server.mu_detect_log_list[
                                    self._current_user_id]:
                            self._server.mu_detect_log_list[
                                self._current_user_id].append(id)
                    else:
                        if self._server.is_cleaning_detect_log == False and id not in self._server.detect_log_list:
                            self._server.detect_log_list.append(id)
                    self._handle_detect_rule_match(remote_port)

                    print (
                        'This connection match the regex: id:%d was reject,regex: %s ,%s connecting %s:%d from %s:%d via port %d' %
                        (self._server.detect_text_list[id]['id'],
                         self._server.detect_text_list[id]['regex'],
                         (connect_type == 0) and 'TCP' or 'UDP',
                         common.to_str(remote_addr),
                         remote_port,
                         self._client_address[0],
                         self._client_address[1],
                         self._server._listen_port))


    def detect2(self, data, remote_addr, remote_port, connect_type):
        pass
        # if not self._server.is_pushing_detect_text_list:
        #     for id in self._server.detect_text_list:
        #         if common.match_regex(
        #                 self._server.detect_text_list[id]['regex'], str(data)):
        #             if self._config['is_multi_user'] != 0 \
        #                     and self._current_user_id != 0:
        #                 if self._server.is_cleaning_mu_detect_log_list == False and id not in \
        #                         self._server.mu_detect_log_list[
        #                             self._current_user_id]:
        #                     self._server.mu_detect_log_list[
        #                         self._current_user_id].append(id)
        #             else:
        #                 if self._server.is_cleaning_detect_log == False and id not in self._server.detect_log_list:
        #                     self._server.detect_log_list.append(id)
        #             self._handle_detect_rule_match(remote_port)
        #
        #             print (
        #                 'This connection match the regex: id:%d was reject,regex: %s ,%s connecting %s:%d from %s:%d via port %d' %
        #                 (self._server.detect_text_list[id]['id'],
        #                  self._server.detect_text_list[id]['regex'],
        #                  (connect_type == 0) and 'TCP' or 'UDP',
        #                  common.to_str(remote_addr),
        #                  remote_port,
        #                  self._client_address[0],
        #                  self._client_address[1],
        #                  self._server._listen_port))

        # raise Exception(
        #     'This connection match the regex: id:%d was reject,regex: %s ,%s connecting %s:%d from %s:%d via port %d' %
        #     (self._server.detect_text_list[id]['id'],
        #      self._server.detect_text_list[id]['regex'],
        #      (connect_type == 0) and 'TCP' or 'UDP',
        #      common.to_str(remote_addr),
        #      remote_port,
        #      self._client_address[0],
        #      self._client_address[1],
        #      self._server._listen_port))

class DetectData(object):
    def __init__(self,data,remote_addr,remote_port,connecttype):
        self._data=data
        self._remote_addr=remote_addr
        self._remote_port=remote_port
        self._connect_type=connecttype


def test():
    print '------------test-------------'
