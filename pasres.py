import time
import struct
import bitstring
# """" "db 42 01 00 00 01 00 01 00 00 00 00 03 77 77 77 " \
# "0c 6e 6f 72 74 68 65 61 73 74 65 72 6e 03 65 64 " \
# "75 00 00 01 00 01 c0 0c 00 01 00 01 00 00 02 58 " \
# "00 04 9b 21 11 44" """
#
# pac_ans2 = "AD 31 81 A0 00 01 00 05 00 00 00 01 02 72 75 00 " \
#            "00 02 00 01 C0 0C 00 02 00 01 00 00 22 29 00 10 " \
#            "01 61 03 64 6E 73 04 72 69 70 6E 03 6E 65 74 00 " \
#            "C0 0C 00 02 00 01 00 00 22 29 00 04 01 62 C0 22 " \
#            "C0 0C 00 02 00 01 00 00 22 29 00 04 01 64 C0 22 " \
#            "C0 0C 00 02 00 01 00 00 22 29 00 04 01 65 C0 22 " \
#            "C0 0C 00 02 00 01 00 00 22 29 00 04 01 66 C0 22 " \
#            "00 00 29 02 00 00 00 00 00 00 00"
#
# pac_ans = "13 F2 81 A0 00 01 00 00 00 01 00 01 02 72 75 00 " \
#           "00 01 00 01 C0 0C 00 06 00 01 00 00 00 F2 00 31 " \
#           "01 61 03 64 6E 73 04 72 69 70 6E 03 6E 65 74 00 " \
#           "0A 68 6F 73 74 6D 61 73 74 65 72 C0 26 00 3D 8C " \
#           "10 00 01 51 80 00 00 38 40 00 27 8D 00 00 00 0E " \
#           "10 00 00 29 02 00 00 00 00 00 00 00"
#
# b_iter = (int(byte, base=16) for byte in pac_ans2.split(" "))
# real_pac2 = bytes(b_iter)
#
# pac1 = b"\xdb\x42\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x77\x77\x77" \
#        b"\x0c\x6e\x6f\x72\x74\x68\x65\x61\x73\x74\x65\x72\x6e\x03\x65\x64" \
#        b"\x75\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x58" \
#        b"\x00\x04\x9b\x21\x11\x44"


def parse_asked_package(package):
    queries = []
    position = 0
    header_unpaker = struct.Struct(">H2sHHHH")
    id, flags, num_q, num_ans, num_aa, num_ar = header_unpaker.unpack(package[:header_unpaker.size])
    position += header_unpaker.size
    for i in range(num_q):  # считываем вопросы
        d_name, type_q, tmp_pos = parse_query(package, position)
        queries.append((d_name, type_q))
        position = tmp_pos
    return id, queries


def parse_answer_package(package):
    """Флаги сервера могут содержать сообщения об ошибке"""
    answers = []
    position = 0
    header_unpaker = struct.Struct(">H2sHHHH")
    id, flags, num_q, num_ans, num_aa, num_ar = header_unpaker.unpack(package[:header_unpaker.size])
    # print(flags)
    r_code = parse_flags(flags)
    position += header_unpaker.size

    for i in range(num_q):  # считываем запросы
        d_name, type_q, tmp_pos = parse_query(package, position)
        position = tmp_pos

    for i in range(num_ans):
        d_name, typeq, remove_time, r_data, tmp_pos = parse_resource_record(package, position)
        position = tmp_pos
        if typeq == 1 or typeq == 2 or typeq == 6:
            answers.append((typeq, d_name, remove_time, r_data))

    for i in range(num_aa):
        d_name, typeq, remove_time, r_data, tmp_pos = parse_resource_record(package, position)
        position = tmp_pos
        if typeq == 1 or typeq == 2 or typeq == 6:
            answers.append((typeq, d_name, remove_time, r_data))

    for i in range(num_ar):
        d_name, typeq, remove_time, r_data, tmp_pos = parse_resource_record(package, position)
        position = tmp_pos
        if typeq == 1 or typeq == 2 or typeq == 6:
            answers.append((typeq, d_name, remove_time, r_data))
    return r_code, answers


def parse_query(package, pos):
    """There only question package part -- name
    type_pack : A ~ 1; NS ~ 2, SOA ~ 6
    :return normal domain naim, type, position
    """
    cur_pos = pos
    domain_name_part, used_bytes = parse_name(package, pos)
    domain_name = ".".join([x.decode() for x in domain_name_part]) + "."
    cur_pos += used_bytes  # index type (2bytes) + class(2bytes) after
    type_pac = struct.unpack(">H", package[cur_pos:cur_pos + 2])[0]
    cur_pos += 4  # number of next part (2bytes - type + 2bytes - class)
    return domain_name, type_pac, cur_pos


def parse_resource_record(package, pos):
    """получаем ответ"""
    domain_name, type_q, tmp_pos = parse_query(package, pos)
    cur_pos = tmp_pos
    ttl, r_data_length = struct.unpack(">IH", package[cur_pos:cur_pos + 6])  # время в секундах
    remove_time = time.time() + ttl
    cur_pos = tmp_pos + 6  # здесь начинаются различия, которые обрабатываются в parse_rdata для каждого из трёх типов
    r_data = parse_rdata(package, cur_pos, type_q, r_data_length)
    cur_pos += r_data_length
    return domain_name, type_q, remove_time, r_data, cur_pos


def parse_rdata(package, pos, type, rdata_len):
    if type == 1:
        bdata = package[pos:pos + 4]
        ip = ".".join(str(byte) for byte in bdata)
        return ip
    if type == 2:
        tmp_res, _ = parse_name(package, pos)
        domain_name = ".".join([x.decode() for x in tmp_res]) + "."
        return domain_name
    if type == 6:
        pr_name_s_list, tmp_pos = parse_name(package, pos)
        primary_name_server = ".".join([x.decode() for x in pr_name_s_list]) + "."
        pos += tmp_pos
        hstmr, tmp_pos = parse_name(package, pos)
        hostmaster = ".".join([x.decode() for x in hstmr]) + "."
        pos += tmp_pos
        serial_number, refresh_inter, retry_inter, expire_limit, min_ttl = struct.unpack(">IIIII", package[pos:pos + 20])
        pos += 20
        return primary_name_server, hostmaster, serial_number, refresh_inter, retry_inter, expire_limit, min_ttl

def parse_name(package, start_pos):
    """
    :return: list bytes of part ONE domain name, count read byte
    """
    result = []
    pos = start_pos
    # print(len(package))
    while True:
        cur_name_len = package[pos]
        if cur_name_len == 0:
            return result, pos - start_pos + 1
        if cur_name_len >= 192:
            tmp_link = struct.unpack(">H", package[pos:pos+2])[0]
            tmp_link -= struct.unpack(">H", b"\xc0\x00")[0]  # ссылка на место куска имени
            result.extend(parse_name(package, tmp_link)[0])
            pos+=2
            return result, pos - start_pos
        pos += 1
        cur_name = package[pos: pos + cur_name_len]
        result.append(cur_name)
        pos += cur_name_len


def parse_flags(flags):
    """ 0120
    QR - query type:
         0 - request
         1 - answer

    opcode - operation code:
         0 - std query, 1 - inverse query, 2 - server status request

    AA - authoritative answer
    TC - truncated
    RD - recursion desired
    RA - recursion available

    rcode - return code:
         0 - ok
         1 - format error
         2 - server failure
         3 - name error
         4 - not implemented
         5 - refused"""

    flag_format = "uint:1, uint:4, bool, bool, bool, bool, uint:3, uint:4"
    flags_tuple = bitstring.BitArray(flags).unpack(flag_format)
    QR, opcode, AthAns, TC, RDes, RAllow, Z, rcode = flags_tuple
    return rcode


if __name__ == "__main__":
        # a = b'\x02ru\x00\x00\x02\x00\x01\x00\x00E\xcc\x00\x10\x01a\x03dns\x04ripn\x03net\x00'
        # print(parse_resource_record(a, 0))
        # print(real_pac2)
        # real_pac3 = b'\x0e\xfb\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x02ru\x00\x00\x02\x00\x01\x02ru\x00\x00\x02\x00\x01\x00\x00-]\x00\x10\x01a\x03dns\x04ripn\x03net\x00\x02ru\x00\x00\x02\x00\x01\x00\x00-]\x00\x10\x01b\x03dns\x04ripn\x03net\x00\x02ru\x00\x00\x02\x00\x01\x00\x00-]\x00\x10\x01d\x03dns\x04ripn\x03net\x00\x02ru\x00\x00\x02\x00\x01\x00\x00-]\x00\x10\x01e\x03dns\x04ripn\x03net\x00\x02ru\x00\x00\x02\x00\x01\x00\x00-]\x00\x10\x01f\x03dns\x04ripn\x03net\x00'
        p = b'\x9a\xe4\x81\x80\x00\x01' \
            b'\x00\x01\x00\x00\x00\x01\x02\x65\x31\x02\x72\x75\x00\x00\x06\x00' \
            b'\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x01\x2b\x00\x23\x03\x6e\x73' \
            b'\x31\xc0\x0c\x06\x61\x64\x6d\x69\x6e\x73\xc0\x0c\x78\x48\x6a\x44' \
            b'\x00\x00\x03\x84\x00\x00\x01\x2c\x00\x27\x8d\x00\x00\x00\x01\x2c' \
            b'\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x00'
        # print(parse_answer_package(p))
        # for nore in a:
        #     print(nore)
        # print(parse_flags(b'\x81\xa3'))
        # pac_soa = b''
        # print(parse_query(p, 12))
        # print(parse_resource_record(p, 23))
