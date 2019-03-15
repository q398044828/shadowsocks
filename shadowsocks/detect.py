#!/usr/bin/python
# coding=utf-8

#
#   根据审计规则，异步检查流量是否违规，违规的中断连接配置的时间长度
#

# yum install -y python-gevent

import logging
import common
import gevent


class DetectHandler(object):
    def __init__(self, server):
        self._server = server
        print ".......... detect handler init ..."

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

    # 使用gevent异步调用审查函数
    def async_detect(self, data, remote_addr, remote_port, connect_type):
        try:
            detect = gevent.spawn(self.detect, data, remote_addr, remote_port, connect_type)
            gevent.joinall([detect])
        except Exception as e:
            logging.error('myError->: 规则审查异常 %s ' % (e))

    def detect(self, data, remote_addr, remote_port, connect_type):
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
                    print '------------------------ 违规请求 --------------------------'


def test():
    print '------------test-------------'
