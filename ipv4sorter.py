
import ipaddress
import csv
import requests
import urllib3
import json
import re
import time
import os.path


#binary tree class for truncating networks
class Subnet():

    def __init__(self, prefix, s1=None, s2=None, address=None):
        self.prefix = prefix
        self.addresses = address
        subs = list(self.prefix.subnets())
        #print(self.prefix, self.addresses)
        if self.prefix.prefixlen >= 29:
            self.s1 = None
            self.s2 = None
        else:
            l1 = [ip for ip in self.addresses if ip in subs[0]]
            l2 = [ip for ip in self.addresses if ip in subs[1]]
            self.s1 = Subnet(subs[0],address=l1) if len(l1)>0 else None
            self.s2 = Subnet(subs[1],address=l2) if len(l2)>0 else None

    def addr_len(self):
        return len(self.addresses)

    def max_pointer(self):
        if self.s1 is None and self.s2 is None:
            return None
        elif self.s1 is None:
            return self.s2
        elif self.s2 is None:
            return self.s1
        else:
            if self.s1.addr_len() >= self.s2.addr_len():
                return self.s1
            else:
                return self.s2

    def walk_sub(self):
        walk_list = [(self.addr_len(),self.prefix)]
        point = self.max_pointer()
        while point != None:
            walk_list.append((point.addr_len(),point.prefix))
            point = point.max_pointer()
        return walk_list

    def walk(self):
        walk_list = [self.addr_len()]
        point = self.max_pointer()
        while point != None:
            walk_list.append(point.addr_len())
            point = point.max_pointer()
        return walk_list

    def reverse_walk(self):
        rule_set = {29: 0.4,
                    28: 0.3,
                    27: 0.225,
                    26: 0.175,
                    25: 0.15,
                    24: 0.125}
        prfx_info = None
        for pair in reversed(self.walk_sub()):
            if (pair[0]/pair[1].num_addresses)<rule_set.get(pair[1].prefixlen):
                break
            else:
                prfx_info = pair
        return prfx_info

#эта штука собирает все /24 сети, хосты которых засветились в blacklist
def ipsorter(ip_list):
    size_subnets = dict()
    for ip in ip_list:
        ipv4 = ipaddress.ip_interface(ip + "/" + str("24"))
        if size_subnets.get(str(ipv4.network)) is None:
            size_subnets[str(ipv4.network)] = [ipv4]
        else:
            size_subnets[str(ipv4.network)].append(ipv4)
    size_report = dict(sorted(size_subnets.items(), key=lambda item: len(item[1]), reverse=True))

    #эта херня нужна для сохранения статистики, буду благодарен если эта тема выживет
    filename = "STATS-" + time.strftime("%m%d-%H%M%S") + ".csv"

    #megalist и есть структура содержащая /32-/24 сетки
    megalist = list()
    reduction = dict()
    saved_lines = 0
    bad_block = 0
    with open(filename, "a", newline='', encoding="utf-8") as output:
        csv_out = csv.writer(output)
        for sub, counter in size_report.items():
            ipv4net = ipaddress.ip_network(sub)
            tree = Subnet(ipv4net, address=counter)
            csv_out.writerow(tree.walk())
            target = tree.reverse_walk()
            if target is None:
                megalist.extend([str(ip.ip)+"/32" for ip in counter])
            else:
                reduction[target[1].prefixlen] = reduction.get(target[1].prefixlen, 0) + 1
                saved_lines += target[0] - 1
                bad_block += target[1].num_addresses - target[0]
                megalist.extend([str(ip.ip) + "/32" for ip in counter if ip not in target[1]])
                megalist.append(str(target[1]))
        #это тупо репорт чтобы оценить последствия объединения в подсетки
        for iterator in range(24,30):
            try:
                print(f"/{iterator}: {reduction[iterator]}")
            except:
                print(f"/{iterator}: 0")
        print("source ip num:", len(ip_list))
        print("saved lines:", saved_lines)
        print("bad blocks:", bad_block)
    return megalist
if __name__ == '__main__':
    print (ipsorter(['192.168.1.1','192.168.2.1','192.168.3.1']))


