from datetime import datetime
from dpwall import parse_dp_info_v2, get_appwall_info_v2

if __name__ == '__main__':
    print("parsing DP cfg from file:")
    dp_list_ec01 = parse_dp_info_v2("10.6.32.193_config.txt")[1]
    dp_list_ec02 = parse_dp_info_v2("10.6.32.192_config.txt")[1]

    dp_list = dp_list_ec01 + dp_list_ec02
    iplist_fromDP = [x[2] for x in dp_list]
    print('-------------------')
    print("getting AppWall cfg via REST API:")
    iplist_ec11 = get_appwall_info_v2('10.6.32.116')
    iplist_ec21 = get_appwall_info_v2('10.6.32.113')
    iplist_ec12 = get_appwall_info_v2('10.6.32.117')
    iplist_ec22 = get_appwall_info_v2('10.6.32.112')
    iplist_total = list(set(iplist_ec11 + iplist_ec12 + iplist_ec21 + iplist_ec22 + iplist_fromDP))

    print(f'Data from DP total length: {len(iplist_fromDP)}')
    print(f'APPWall 1 EC01 ip list total length: {len(iplist_ec11)}')
    print(f'APPWall 2 EC01 ip list total length: {len(iplist_ec12)}')
    print(f'APPWall 1 EC02 ip list total length: {len(iplist_ec21)}')
    print(f'APPWall 2 EC02 ip list total length: {len(iplist_ec22)}')
    print(f'APPWall ip list total length: {len(iplist_total)}')

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f"brand_new_dp_cfg_add_{timestamp}.txt", "w") as fh, open(f"brand_new_dp_cfg_del_{timestamp}.txt", "w") as fh2:
        fh.write(gen_brand_new_dp_cfg(iplist_total)[0])
        fh2.write(gen_brand_new_dp_cfg(iplist_total)[1])
    with open("brand_new_iplist.txt", "w") as fh:
        fh.writelines(iplist_total)
