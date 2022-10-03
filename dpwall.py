import urllib3
import json
import re
import time
import os.path
from requests.structures import CaseInsensitiveDict
from datetime import datetime
import requests


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_appwall_info(apw_ip):
    url = f"https://{apw_ip}/v2/config/aw/BlockedSources"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    attempt = 1  # trying to get data by REST API:
    while attempt < 4:
        try:
            print(f'Trying to fetch url: {url}, attempt {attempt}')
            json_data = json.loads(requests.get(url, verify=False, auth=('admin', 'P@ssw0rd!@#')).text)
            ip_addr_list = list()
            for item in json_data['BlockedSources']:
                ip_addr_list.append(item['SourceId'])
            break
        except Exception as err:
            exception_type = type(err).__name__
            print(f'exception occured: {exception_type}, trying again in 10 sec')
            time.sleep(10)
        finally:
            attempt += 1
    return ip_addr_list


def get_files():
    ip_list = []
    folder = "./filedb"
    for file in os.listdir(folder):
        filepath = os.path.join(folder, file)
        print(f"reading a file: {filepath}")
        with open(filepath, "r") as fh:
            ip_list += fh.read().splitlines()
    return ip_list


def put_files(ip_list, folder="./filedb"):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filepath = os.path.join(folder, f"filedb_{timestamp}.txt")
    with open(filepath, "w") as fh:
        print(f'writing to file: {filepath}')
        fh.write("\n".join(ip_list))


def put_soap(full_cfg_string=str(), host=str()):
    full_cfg_list = full_cfg_string.splitlines()
    cfg_chunks_list = [full_cfg_list[x:x + 250] for x in range(0, len(full_cfg_list), 250)]
    for cfg_chunk_list in cfg_chunks_list:
        print("putting CHUNK:", cfg_chunk_list)
        cfg_chunk_string = "\n".join(cfg_chunk_list)

        url = f"https://{host}/soap"

        headers = CaseInsensitiveDict()
        headers["Content-Type"] = "text/xml;charset=UTF-8"
        headers["Accept-Encoding"] = "gzip,deflate"
        headers["SOAPAction"] = "DeviceConfigurationAction"
        headers["Connection"] = "Keep-Alive"

        soap_data_tmplt = f"""
        <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:rad="radware.Device.Configuration">
           <soapenv:Header/>
           <soapenv:Body>
              <rad:append_Config soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                 <config xsi:type="xsd:string">{cfg_chunk_string}  

                  </config>
              </rad:append_Config>
           </soapenv:Body>
        </soapenv:Envelope>
        """
        resp = requests.post(url, headers=headers, data=soap_data_tmplt, verify=False,
                             auth=('username', 'password')).text

        print(resp)


def get_soap_fullcfg(host=str()):
    url = f"https://{host}/soap"

    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "text/xml;charset=UTF-8"
    headers["Accept-Encoding"] = "gzip,deflate"
    headers["SOAPAction"] = "DeviceConfigurationAction"
    headers["Connection"] = "Keep-Alive"

    soap_data_tmplt = f"""
    <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:rad="radware.Device.Configuration">
        <soapenv:Header/>
        <soapenv:Body>
            <rad:get_Config soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
        </soapenv:Body>
    </soapenv:Envelope>
    """
    resp = requests.post(url, headers=headers, data=soap_data_tmplt, verify=False,
                         auth=('nspk-noc', 'P@ssw0rd!@#')).text
    return resp.replace("\\\r\n", "")


def parse_dp_info_v2(raw_cfg):
    """returns a dict with APW_names of corresponding lists of seqNo/IP's inside"""
    regexpr_class = "classes modify network create (APW_SCRIPT_\d\d?\d?) (\d+) -a (\d\d?\d?.\d\d?\d?.\d\d?\d?.\d\d?\d?) -s (\d\d?)"
    dp_array = [x.groups() for x in re.finditer(regexpr_class, raw_cfg)]
    # converting dp list to dictionary:
    # get unique set of class names from dp array:
    apws_names = {dp_array[item_num][0] for item_num in range(len(dp_array))}
    dp_dict = dict()
    # get an index numbers from dp_array for each class name:
    for apws_name in apws_names:
        apws_item_indexlist = [index for index, value in enumerate(dp_array) if value[0] == apws_name]
        dp_dict[apws_name] = [[int(dp_array[index][1]), dp_array[index][2], dp_array[index][3]] for index in
                              apws_item_indexlist]
    return dp_dict, dp_array


def gen_diff_dp_appwall(dp_cfg_dict=dict(), iplist_appwall=list()):
    # for all classes in a dp dict generate a common dp list:
    iplist_dpro = list()
    for apw_item in dp_cfg_dict:
        iplist_dpro += [item[1] for item in dp_cfg_dict[apw_item]]

    # print some debug:
    print('iplist_dpro len = ', len(iplist_dpro))
    print('ip_appwall_list orig len = ', len(iplist_appwall))

    # if an item from iplist dpro exists in iplist_appwall - remove it from appwall list
    for item in iplist_dpro:
        if item in iplist_appwall: iplist_appwall.remove(item)
    print('ip_appwall_new list len', len(iplist_appwall))
    return iplist_appwall


def get_free_spotes(arr):
    cur_index = []  # make and populate a list with current seqNo
    for group in arr:
        cur_index.append(group[0])
    free = []  # free index list
    for z in range(0, 250):
        if z not in cur_index:  # if current list index is not in current index list - add to free index list
            free.append(z)
    return free


def gen_dp_dictv2(dp_dict=dict(), iplist_diffed=list()):
    free_APW = []  # make a dictionary describing a free seqNo's in a class and their length
    ips_count_to_insert = 0  # this is to watch for the offset of inserted IP's count.

    # insertion into an existing classes:
    for key, value in dp_dict.items():
        if len(
                value) < 250:  # if class is not full - insert b_dict containing a class name and free spots positions and len.
            b_dict = {"class": key,
                      "free": get_free_spotes(value),
                      "len_free": len(get_free_spotes(value))}
            free_APW.append(b_dict.copy())
            ips_count_to_insert += b_dict[
                "len_free"]  # increment total inserted IP's count by number of free slots found
    print("-------------------------------")

    # after using existing classes - make more classes to fill by remaining IPs
    # TODO: DONE this may cause to identify wrong last class num if the last class was full at the beginning and didn't appear in free_APW.
    max_exist_class_num = max(sorted([int(x[11:]) for x in
                                      dp_dict.keys()]))  # for each class name  in free_APW find it's numbers and a max num. It's to determine the num of new class
    # max_exist_class_num = max(sorted([int(x.get('class')[11:]) for x in free_APW])) #for each class name  in free_APW find it's numbers and a max num. It's to determine the num of new class
    print("Max_class_number_exists:", max_exist_class_num)
    print("total IPs count to insert to existent dict:", ips_count_to_insert)
    new_apws_needed = (len(
        iplist_diffed) - ips_count_to_insert) // 250  # Let's find how many new class names do we need to fill it with ip's.
    remainder = (len(iplist_diffed) - ips_count_to_insert) % 250  # After this - fill the last class with the rest
    print(f'new_apws_needed = {new_apws_needed}, remainder = {remainder}')
    for new_apw_num in range(max_exist_class_num + 1,
                             max_exist_class_num + new_apws_needed + 1):  # populate free_APW with new entries filled with 250 free spots
        free_APW.append({'class': 'APW_SCRIPT_' + str(new_apw_num),
                         'free': [x for x in range(250)],
                         'len_free': 250})
    free_APW.append({'class': 'APW_SCRIPT_' + str(new_apw_num + 1),
                     # after filling all the full classes - create the last one and fill it with necessary free spots
                     'free': [x for x in range(remainder)],
                     'len_free': remainder})
    free_APW = sorted(free_APW, key=lambda x: x.get("class"))

    print("need to configure:", len(iplist_diffed))
    for cl in free_APW:
        print(f'className = {cl.get("class")}, free spots: {cl.get("len_free")}')

    APW_dict = dict()  # actual dict we should fill in
    # #create data structure with names from free_APW
    for apws_names in [x.get('class') for x in free_APW]:
        APW_dict[apws_names] = []  # and define each one as a list

    # let's fill actual dict using free_APW list we made:
    ip_iterator = 0  # iterator which goes through ip list
    apw_iterator = 0  # iterates via apw name
    while ip_iterator < len(iplist_diffed):  # external loop for the ip list

        if len(free_APW[apw_iterator].get(
                "free")) == 0:  # if there is no free spots remaining - go to the next apw iteration
            apw_iterator += 1
            continue
        else:  # if spots still remain:
            # append list(seqNo,IP)  the corresponding APW_dict[apw name]
            APW_dict[free_APW[apw_iterator].get('class')].append(
                [free_APW[apw_iterator].get('free')[0], iplist_diffed[ip_iterator]])
            # debug info for free APW: print("added class = ", free_APW[apw_iterator].get("class"), "free = ", free_APW[apw_iterator].get("free")[0], iplist_diffed[ip_iterator])
            free_APW[apw_iterator]["free"].pop(0)  # remove seqNo from corresponding free slot list
            ip_iterator += 1  # increment pos for ip list
    return APW_dict


def gen_dp_cfg(dp_cfg_generated_dict=dict()):
    '''generates lines for Defense Pro using a DP dict with class names and seq numbers'''
    classes_create_cfgline, classes_delete_cfgline, blklst_table_create_cfgline, blklst_table_delete_cfgline = "", "", "", ""
    for classname in dp_cfg_generated_dict:
        blklst_table_create_cfgline += f'dp block-allow-lists blocklist table create {classname} -sn {classname}\n'
        blklst_table_delete_cfgline += f'dp block-allow-lists blocklist table del {classname}\n'
        for seqno, ipaddr, prefixlen in dp_cfg_generated_dict[classname]:
            classes_create_cfgline += f'classes modify network create {classname} {seqno} -a {ipaddr} -s {prefixlen}\n'
            classes_delete_cfgline += f'classes modify network del {classname} {seqno}\n'
    cfg_line = "===ADD CLASSES SECTION===\n" + classes_create_cfgline + "\n===ADD TABLES SECTION===\n" + blklst_table_create_cfgline + "\n===DEL CLASSES SECTION===\n" + classes_delete_cfgline + "\n===DEL TABLES SECTION===\n" + blklst_table_delete_cfgline

    return (classes_create_cfgline + blklst_table_create_cfgline, classes_delete_cfgline + blklst_table_delete_cfgline)


def gen_brand_new_dp_cfg(iplist):
    """generates text config out of list - with masks.
    Returns two strings. First is for adding config and second - for deleting"""

    chunks = [iplist[x:x + 250] for x in range(0, len(iplist), 250)]
    cfg_str_classes_add, cfg_str_blcktables_add, cfg_str_classes_del, cfg_str_blcktables_del = "", "", "", ""
    for classnum in range(0, len(chunks)):
        cfgline = f'dp block-allow-lists blocklist table create APW_SCRIPT_{classnum} -sn APW_SCRIPT_{classnum}\n'
        cfg_str_blcktables_add = cfg_str_blcktables_add + cfgline
        cfgline = f'dp block-allow-lists blocklist table del APW_SCRIPT_{classnum}\n'
        cfg_str_blcktables_del = cfg_str_blcktables_del + cfgline
        for ipnum in range(0, len(chunks[classnum])):
            if chunks[classnum][ipnum].find("/") != -1:  # see if network mask exists and substring it.
                netaddr = chunks[classnum][ipnum][:chunks[classnum][ipnum].find("/")]
                prefixlen = chunks[classnum][ipnum][chunks[classnum][ipnum].find("/") + 1:]
            else:  # if there is no "/" in item - assume that prefix len is 32
                netaddr = chunks[classnum][ipnum]
                prefixlen = 32
            cfgline = f'classes modify network create APW_SCRIPT_{classnum} {ipnum} -a {netaddr} -s {prefixlen}\n'
            cfg_str_classes_add = cfg_str_classes_add + cfgline
            cfgline = f'classes modify network del APW_SCRIPT_{classnum} {ipnum}\n'
            cfg_str_classes_del = cfg_str_classes_del + cfgline
    cfg_str_add = cfg_str_classes_add + cfg_str_blcktables_add
    cfg_str_del = cfg_str_classes_del + cfg_str_blcktables_del
    cfg_str = "===ADD SECTION===\n" + cfg_str_add + "===DELETE SECTION===\n" + cfg_str_del + "\n"
    return (cfg_str_add, cfg_str_del)


if __name__ == '__main__':
    print('the module is not intended to run directly')
