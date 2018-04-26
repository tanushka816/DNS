import time
import socket
from cache import cache_clear
from pasres import parse_asked_package, parse_answer_package
from pack_builder import build_answer, make_name_bytes
from collections import defaultdict

PORT = 53
SERVER1 = '8.8.8.8'
# SERVER3 = '192.168.43.15'
# SERVER2 = '212.193.163.6'
SERVER = SERVER1

CACHE_A = defaultdict(dict)
CACHE_NS = defaultdict(dict)
CACHE_SOA = defaultdict(dict)
GLOBAL_CACHE = {1: CACHE_A, 2: CACHE_NS, 6: CACHE_SOA}


def start(server=SERVER):
    print("started")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', PORT))
    while True:
        data, sender = sock.recvfrom(512)
        finall_package = resolve_data(data, server)
        sock.sendto(finall_package, sender)


def resolve_data(data, server=SERVER):
    answer_package = b''

    global CACHE_A
    global CACHE_NS
    global GLOBAL_CACHE

    global GLOBAL_CACHE
    id, questions = parse_asked_package(data)
    all_ans = []
    CACHE_A = cache_clear(GLOBAL_CACHE[1])
    CACHE_NS = cache_clear(GLOBAL_CACHE[2])
    CACHE_SOA = cache_clear(GLOBAL_CACHE[6])
    GLOBAL_CACHE = {1: CACHE_A, 2: CACHE_NS, 6: CACHE_SOA}
    for d_name, qtype in questions:
        # print(d_name)
        # print(qtype)
        if qtype in GLOBAL_CACHE:
            # print(GLOBAL_CACHE[qtype])
            if d_name in GLOBAL_CACHE[qtype]:
                for addr in GLOBAL_CACHE[qtype][d_name].keys():
                    rem_time = GLOBAL_CACHE[qtype][d_name][addr]
                    ttl = rem_time - time.time()
                    ttl = int(ttl)
                    if ttl > 0:
                        all_ans.append((qtype, d_name, ttl, addr))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(data, (SERVER, PORT))
                data = sock.recv(512)
                answer_package = data

                rcode, answers = parse_answer_package(data)
                # print(answers)
                cur_time = time.time()

                if rcode == 0:
                    for ans in answers:
                        qtype, d_name, remove_time, rdata = ans
                        # print(remove_time)
                        if qtype not in GLOBAL_CACHE:
                            continue
                        # print(rdata)
                        # print(type(rdata))
                        # GLOBAL_CACHE[qtype][d_name][rdata] = 2
                        # print(GLOBAL_CACHE)
                        # if qtype == 1 or qtype == 2:
                        GLOBAL_CACHE[qtype][d_name][rdata] = remove_time
                        ttl = remove_time - cur_time
                        ttl = int(ttl)
                        # print(ttl)
                        all_ans.append((qtype, d_name, ttl, rdata))
                        # elif qtype == 6:
                        #     pr_name = ''
                        #     hst_name = ''
                        #     pr_name_list = rdata[0]
                        #     for x in pr_name_list:
                        #         pr_name+=x.decode()
                        #     print(pr_name)
                        #     hst_name_list = rdata[1]
                        #     for x in hst_name_list:
                        #         hst_name += x.decode()
                        #     print(hst_name)
                            # hst_name = make_name_bytes(rdata[1])
                            # rdata1 = tuple(pr_name, hst_name, rdata[2:])
                            # print(rdata1)
                print(GLOBAL_CACHE)
    if len(all_ans) == 0:
        rcode = 3
    else:
        rcode = 0

    if not answer_package:
        answer_package = build_answer(id, rcode, questions, all_ans)
    return answer_package



if __name__ == "__main__":
    start()