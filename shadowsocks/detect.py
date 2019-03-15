#!/usr/bin/python
# coding=utf-8

#
#   根据审计规则，异步检查流量是否违规，违规的中断连接配置的时间长度
#

# yum install -y python-gevent


import common


class DetectHandler(object):
    def __init__(self, relay_handler):
        self._relay_handler = relay_handler
        print "detect handler init..."

    def detect(self, data, remote_addr,remote_port,connect_type):
        if not self._relay_handler._server.is_pushing_detect_text_list:
            for id in self._relay_handler._server.detect_text_list:
                if common.match_regex(
                        self._relay_handler._server.detect_text_list[id]['regex'], str(data)):
                    if self._relay_handler._config['is_multi_user'] != 0 \
                            and self._relay_handler._current_user_id != 0:
                        if self._relay_handler._server.is_cleaning_mu_detect_log_list == False and id not in \
                                self._relay_handler._server.mu_detect_log_list[
                                    self._relay_handler._current_user_id]:
                            self._relay_handler._server.mu_detect_log_list[
                                self._relay_handler._current_user_id].append(id)
                    else:
                        if self._relay_handler._server.is_cleaning_detect_log == False and id not in self._relay_handler._server.detect_log_list:
                            self._relay_handler._server.detect_log_list.append(id)
                    self._relay_handler._handle_detect_rule_match(remote_port)

                    print (
                        'This connection match the regex: id:%d was reject,regex: %s ,%s connecting %s:%d from %s:%d via port %d' %
                        (self._relay_handler._server.detect_text_list[id]['id'],
                         self._relay_handler._server.detect_text_list[id]['regex'],
                         (connect_type == 0) and 'TCP' or 'UDP',
                         common.to_str(remote_addr),
                         remote_port,
                         self._relay_handler._client_address[0],
                         self._relay_handler._client_address[1],
                         self._relay_handler._server._listen_port))

                    # raise Exception(
                    #     'This connection match the regex: id:%d was reject,regex: %s ,%s connecting %s:%d from %s:%d via port %d' %
                    #     (self._relay_handler._server.detect_text_list[id]['id'],
                    #      self._relay_handler._server.detect_text_list[id]['regex'],
                    #      (connect_type == 0) and 'TCP' or 'UDP',
                    #      common.to_str(remote_addr),
                    #      remote_port,
                    #      self._relay_handler._client_address[0],
                    #      self._relay_handler._client_address[1],
                    #      self._relay_handler._server._listen_port))
