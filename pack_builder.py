import struct
import time
import bitstring
import hexdump


# p = (2, 'ru.', 17868, 'a.dns.ripn.net.')
# d_name = p[1]
# qt = p[0]
# r_d = p[3]
# rt = p[2]

def build_answer(id, rcode, queries, answers):
    # print(answers)
    result = create_header(id, rcode, len(queries), len(answers))
    for d_name, qtype in queries:
        result += create_query(d_name, qtype)

    for qtype, d_name, ttl, rdata in answers:
        result += create_rrecord(d_name, qtype, rdata, ttl)

    return result


def create_header(id, rcode, num_q, num_answ):
    fl = make_flag(rcode)
    result = struct.pack(">H2sHHHH", id, fl, num_q, num_answ, 0, 0)
    return result


def create_query(d_name, qtype):
    result = make_name_bytes(d_name)
    result += struct.pack(">HH", qtype, 1)
    return result


def make_flag(rcode):
    return bitstring.pack("uint:1, uint:4, bool, bool, bool, bool, uint:3, uint:4",
                   1, 0, False, False, True, True, 0, rcode).tobytes()


def create_rrecord(domain_name, qtype, r_data, ttl):
    result = b""
    result += make_name_bytes(domain_name)
    rdata_bytes = make_rdata(qtype, r_data)
    result += struct.pack(">HHIH", qtype, 1, ttl, len(rdata_bytes))
    result += rdata_bytes
    return result


def make_name_bytes(domain_name):
    result = b""
    for name_part in domain_name.split("."):
        b_part = name_part.encode()
        result += bytes((len(b_part), )) + b_part
    if result[-1] != 0:
        result += b"\x00"
    return result


def make_rdata(qtype, r_data):
    if qtype == 1:
        return bytes(int(part) for part in r_data.split("."))
    if qtype == 2:
        return make_name_bytes(r_data)
    if qtype == 6:
        return make_name_bytes(r_data[0]) + make_name_bytes(r_data[1]) + \
                 struct.pack(">IIIII", r_data[2], r_data[3], r_data[4], r_data[5], r_data[6])




# def build_answer():
#     pass


# if __name__ == "__main__":
#     # byt = create_rrecord(d_name, qt, r_d, rt)
#     # print(byt)
#     ans = [(2, 'ru.', 11613, 'a.dns.ripn.net.'), (2, 'ru.', 11613, 'b.dns.ripn.net.'),
#            (2, 'ru.', 11613, 'd.dns.ripn.net.'), (2, 'ru.', 11613, 'e.dns.ripn.net.'),
#            (2, 'ru.', 11613, 'f.dns.ripn.net.')]
#     build_answer(3835, 0, [('ru.', 2)], ans)