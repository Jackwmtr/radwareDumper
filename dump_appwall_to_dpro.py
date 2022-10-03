#!/usr/bin/env python3
import time
import dpwall
import sys

if __name__ == '__main__':
    sys.argv = ["dump_appwall_to_pro.py", "create"]
    if len(sys.argv) == 2: #if we have args - go for it:
        if sys.argv[1]=="create":
            print("deleting classes and networks before creation:")
            print("getting existing classes and block tab...")
            raw_cfg = dpwall.get_soap_fullcfg("10.6.20.233") #TODO: update real dpro address
            dp_dict = dpwall.parse_dp_info_v2(raw_cfg)[0] #get dict
            dp_cfg_del_str = dpwall.gen_dp_cfg(dp_dict)[1] #get delete config string
            dpwall.put_soap(dp_cfg_del_str, "10.6.20.233")
            time.sleep(3)
            dpwall.put_soap(dp_cfg_del_str, "10.6.20.233")
            #-----------CREATE------------------
            print ("creating classes and blocklist tables...")
            print('-------------------')
            print("getting AppWall cfg via REST API:")
            iplist_ec11 = dpwall.get_appwall_info('10.6.32.116') #TODO: update real appwall addresses
            iplist_ec12 = dpwall.get_appwall_info('10.6.32.117')
            iplist_total = list(set(iplist_ec11 + iplist_ec12))
            if len(iplist_total) > 30000:  # trunkate list len to max 30000
                del iplist_total[30000:]
                print("list is too large, truncating it to 30000.")
            dpwall.put_files(iplist_total, "./backupdb")
            print(f'APPWall 1 EC01 ip list total length: {len(iplist_ec11)}')
            print(f'APPWall 2 EC01 ip list total length: {len(iplist_ec12)}')
            print(f'APPWall ip list total length: {len(iplist_total)}')
            print ("generating new configs out of APPWall lists:")
            dp_cfg_str_add = dpwall.gen_brand_new_dp_cfg(iplist_total)[0] #generate cfg string for add
            dpwall.put_soap(dp_cfg_str_add, "10.6.20.233") #TODO: update real dpro address
        if sys.argv[1]=="delete":
            print("getting existing classes and block tab...")
            raw_cfg = dpwall.get_soap_fullcfg("10.6.20.233") #TODO: update real dpro address
            dp_dict = dpwall.parse_dp_info_v2(raw_cfg)[0] #get dict
            dp_cfg_del_str = dpwall.gen_dp_cfg(dp_dict)[1] #get delete config string
            dpwall.put_soap(dp_cfg_del_str, "10.6.20.233")
            time.sleep(3)
            dpwall.put_soap(dp_cfg_del_str, "10.6.20.233")
    else: print("usage: ./scriptname.py create|delete")


