import socket
import signal
import pickle
from datetime import datetime

remote_server = '216.239.34.10' #dns-сервер Google
run = True
cache = {}
timer = datetime.now().timestamp()


def handler_stop_signals(*args):
    global run
    run = False
    clear_cache()
    dump_cache()
    print("Server shutdown")


signal.signal(signal.SIGINT, handler_stop_signals)
signal.signal(signal.SIGTERM, handler_stop_signals)


def dump_cache():
    with open('cache.txt', 'wb') as cache_file:
        pickle.dump(cache, cache_file)


def load_cache() -> dict[tuple, tuple]:
    try:
        with open('cache.txt', 'rb+') as cache_file:
            return pickle.load(cache_file)
    except FileNotFoundError:
        return {}


def clear_cache():
    global timer
    current_time = int(datetime.now().timestamp())
    update_time = current_time - timer
    if update_time >= 60:
        for key, item in cache.copy().items():
            for records in item:
                for record in records:
                    new_ttl = int.from_bytes(record["TTL"], byteorder="big") - 60
                    if new_ttl <= 0:
                        records.remove(record)
                    else:
                        record["TTL"] = new_ttl.to_bytes(4, byteorder='big')
            if item == ([], [], []):
                cache.pop(key)
        timer = current_time


def purse_flags(flags: bytes) -> dict:
    bits = list()
    for byte in flags:
        bit = bin(byte)[2:]
        offset = 8 - len(bit)
        if offset:
            bit = "0" * offset + bit
        bits.append(bit)

    result = dict()

    result["QR"] = bits[0][0]
    result["OPCODE"] = bits[0][1:5]
    result["AA"] = bits[0][5]
    result["TC"] = bits[0][6]
    result["RD"] = bits[0][7]

    # Byte 2

    result["RA"] = bits[1][0]
    result["Z"] = bits[1][1:4]
    result["RCODE"] = bits[1][4:8]

    return result


def purse_header(header: bytes) -> dict:
    result = dict()
    result["transactionID"] = header[:2]
    result["flags"] = purse_flags(header[2:4])
    result["QDCOUNT"] = header[4:6]
    result["ANCOUNT"] = header[6:8]
    result["NSCOUNT"] = header[8:10]
    result["ARCOUNT"] = header[10:12]
    return result


def purse_question(question: bytes) -> dict:
    result = dict()
    result["NAME"] = question[:-4]
    result["TYPE"] = question[-4:-2]
    result["CLASS"] = question[-2:]
    return result


def purse_resource_record(resource_record: bytes) -> (dict, int):
    result = dict()
    result["NAME"] = resource_record[:2]
    result["TYPE"] = resource_record[2:4]
    result["CLASS"] = resource_record[4:6]
    result["TTL"] = resource_record[6:10]
    result["RDLENGTH"] = resource_record[10:12]
    offset = int.from_bytes(result["RDLENGTH"], byteorder='big')
    result["RDDATA"] = resource_record[12: 12 + offset]
    return result, offset + 12


def find_name_and_name_length(dns_package_body: bytes) -> (str, int):
    name_part_length = dns_package_body[0]
    begin = 1
    end = begin + name_part_length
    name_length = name_part_length
    name = ""
    while name_part_length:
        name += dns_package_body[begin: end].decode('866') + "."
        begin = end
        name_part_length = dns_package_body[begin]
        name_length += name_part_length + 1
        begin += 1
        end = begin + name_part_length
    return name, name_length + 1


def purse_dns_package(dns_query: bytes) -> dict:
    result = dict()
    header = purse_header(dns_query[:12])
    name, name_length = find_name_and_name_length(dns_query[12:])
    offset = 12 + name_length + 4
    question = purse_question(dns_query[12: offset])
    if header["flags"]["QR"] != "0":
        answers = list()
        authority = list()
        additional = list()
        an_count = int.from_bytes(header["ANCOUNT"], byteorder='big')
        if an_count:
            for _ in range(an_count):
                answer, new_offset = purse_resource_record(dns_query[offset:])
                offset += new_offset
                answers.append(answer)
        ns_count = int.from_bytes(header["NSCOUNT"], byteorder='big')
        if ns_count:
            for _ in range(ns_count):
                one_authority_record, new_offset = purse_resource_record(dns_query[offset:])
                offset += new_offset
                authority.append(one_authority_record)
        ar_count = int.from_bytes(header["ARCOUNT"], byteorder='big')
        if ar_count:
            for _ in range(ar_count):
                one_additional_record, new_offset = purse_resource_record(dns_query[offset:])
                offset += new_offset
                additional.append(one_additional_record)
        result["body"] = {"header": header,
                          "question": question,
                          "answers": answers,
                          "authority": authority,
                          "additional": additional}
    else:
        result["body"] = {"header": header, "question": question}
    result["key"] = (name,
                     int.from_bytes(result["body"]["question"]["TYPE"],
                                    byteorder='big'))
    return result


def assemble_resource_record(parsed_resource_record: dict) -> bytes:
    if parsed_resource_record:
        result = parsed_resource_record["NAME"]
        result += parsed_resource_record["TYPE"]
        result += parsed_resource_record["CLASS"]
        result += parsed_resource_record["TTL"]
        result += parsed_resource_record["RDLENGTH"]
        result += parsed_resource_record["RDDATA"]
    else:
        result = b''
    return result


def build_response(parsed_dns_query: dict, cache_entry: tuple) -> bytes:
    transactionID = parsed_dns_query["body"]["header"]["transactionID"]
    flags = b'\x85\x00'
    qd_count = b'\x00\x01'
    an_count = len(cache_entry[0]).to_bytes(2, byteorder='big')
    ns_count = len(cache_entry[1]).to_bytes(2, byteorder='big')
    ar_count = len(cache_entry[2]).to_bytes(2, byteorder='big')
    question = parsed_dns_query["body"]["question"]["NAME"]
    question += parsed_dns_query["body"]["question"]["TYPE"]
    question += parsed_dns_query["body"]["question"]["CLASS"]
    resource_records = b''
    for parsed_resource_records in cache_entry:
        for parsed_resource_record in parsed_resource_records:
            resource_records += assemble_resource_record(parsed_resource_record)
    return transactionID + flags + qd_count + an_count + ns_count + ar_count + question + resource_records


def receive_from(some_socket):
    some_socket.settimeout(2)
    try:
        data, address = some_socket.recvfrom(512)
    except TimeoutError:
        data = b''
        address = ""
    return data, address


def server_loop(host: str, port: int):
    locale_dns_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    locale_dns_server.bind((host, port))
    authoritative_dns_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while run:
        locale_dns_server.settimeout(2)
        dns_query, client_address = receive_from(locale_dns_server)
        clear_cache()
        if dns_query:
            parsed_dns_query = purse_dns_package(dns_query)
            if parsed_dns_query["key"] in cache:
                print("get from cache")
                try:
                    locale_dns_server.sendto(build_response(parsed_dns_query=parsed_dns_query,
                                                            cache_entry=cache[parsed_dns_query["key"]]), client_address)
                except:
                    print('There is no access to a client.')
                    continue
            else:
                try:
                    authoritative_dns_server.sendto(dns_query, (remote_server, 53))
                except:
                    print('There is no access to an authoritative dns server.')
                    continue
                authoritative_answer, _ = receive_from(authoritative_dns_server)
                parsed_dns_answer = purse_dns_package(authoritative_answer)
                try:
                    locale_dns_server.sendto(authoritative_answer, client_address)
                except:
                    print('There is no access to a client.')
                    continue
                if parsed_dns_answer["body"]["answers"]:
                    cache[parsed_dns_query["key"]] = (parsed_dns_answer["body"]["answers"],
                                                      parsed_dns_answer["body"]["authority"],
                                                      parsed_dns_answer["body"]["additional"])
                    print("The record has been cached")


def main():
    print("Start server")
    global cache
    cache = load_cache()
    server_loop(host='127.0.0.1', port=53)


if __name__ == '__main__':
    main()
