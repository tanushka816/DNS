import time
import copy
from collections import defaultdict

# cacheA = {'domain_nameA': {'getten IP': 1524241033.5066555,
#                            'another getten IP': 1524241133.5066555},
#           'anoth d n': {'getten IP2': 1524241153.5066555,
#                         'another getten IP2': 1524241203.5066555}}
#
# cacheNS = {'domain_name': {'a.dns.ripn.net.': 1524397550.4171498,
#                            'b.dns.ripn.net.': 1524396907.4171498,
#                            'd.dns.ripn.net.': 1524396227.4171498,
#                            'e.dns.ripn.net.': 1524396967.4171498,
#                            'f.dns.ripn.net.': 1524396867.4171498},
#            'anoth d n': {'getten domain name2': 1524241153.5066555,
#                          'another getten domain name2': 1524241203.5066555}}


def cache_clear(cache):
    """проверка на истёкший ттл"""
    cache_remove_from = copy.deepcopy(cache)

    for d_name in cache.keys():
        # print(note)
        for address_aim in cache[d_name].keys():
            # print(domen_name_key)
            ttl = cache[d_name][address_aim]
            # print(ttl)
            if ttl < time.time():
                print(ttl)
                cache_remove_from[d_name].pop(address_aim)  # очищенный cache_renove_from

    to_delete_d_name = []
    for d_name in cache_remove_from:
        if not cache_remove_from[d_name]:
            to_delete_d_name.append(d_name)

    for d_name in to_delete_d_name:
        cache_remove_from.pop(d_name)

    return cache_remove_from


# def cache_add(cache, inf_dict):
#     """
#     :param inf_dict: словарь словрей - запрашиваемое доменное имя: {ответ: ищменённое ttl, }
#     на случай, если было несколько запросов сразу
#     """
#     result = copy.deepcopy(cache)
#     for d_name in inf_dict.keys():
#         result[d_name] = inf_dict[d_name]
#     return result
#
#
# def del_domen_name(cache):
#     """В случае переполнения кеша
#     удаляем нулевое доменное имя с его записями"""
#     for d_name in cache.keys():
#         d_name_to_del = d_name
#         break
#     cache.pop(d_name_to_del)
#     return cache
#
#
# def in_cache(cache, domain_name):
#     """
#     :return: bool Y/N domain name in cache
#     """
#     return domain_name in cache.keys()
#
#
# def get_from_cache(cache, domain_name):
#     cache_clear(cache)
#     try:
#         return cache[domain_name]
#     finally:
#         return {}
#
#
# if __name__ == "__main__":
#     in_d = {'another d n': {'gotten domain name2': 1524240317.9502885, 'gotten domain name3': 1524240317.9502885}}
#
#     # neew_cache = cache_add(cacheNS, in_d)
#     # c = cache_clear(cacheNS)
#     # print(neew_cache)
#     ne_c = {'domain_name': {'getten domain name': 1524241033.5066555,
#                             'another getten domain name': 1524241133.5066555},
#             'anoth d n': {'getten domain name2': 1524241153.5066555,
#                           'another getten domain name2': 1524241203.5066555},
#             'another d n': {'gotten domain name2': 1524240317.9502885,
#                             'gotten domain name3': 1524240317.9502885}}
#     # print(in_cache(ne_c, 'domain_nameq'))
#     print(cache_clear(cacheNS))

    # print(del_domen_name(neew_cache))
    # print(del_domen_name(neew_cache))
    # print(del_domen_name(neew_cache))
    # l = []
    # # c = {'domain_name': {}, 'another d n': {'getten domain name2': 1524240317.9502885}}
    # for d_name in c.keys():
    #     print(d_name)
    #     if not c[d_name]:
    #         l.append(d_name)
    # print(l)
    # for i in l:
    #     c.pop(i)
    #
    # print(c)
