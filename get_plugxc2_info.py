import argparse
from dotenv import load_dotenv
from time import sleep 

load_dotenv()

shodan_env_key = os.getenv('SHODAN')

api = shodan.Shodan(shodan_env_key)


def write_output(ip, port, banner):
    current = 'path_to_riskiq_plugx_ips.txt'
    with open(current, 'a')as in_file:
        data = in_file.write(str(ip) + ' ' + str(port) + ' ' + str(banner) + '\n')

    return data 


def parse_ipfile_shodan(path):

    with open(path, 'r')as out_file:
        for lines in out_file:
            ips = lines.strip()
            
            try:
                print(f'Gathering Info for {ips}')
                shodan_info = api.host(ips)

                for info in shodan_info['data']:
                    testport = info['port']
                    testbanner = info['data']

                    write_output(ips, testport, testbanner)
                sleep(2)

            except shodan.exception.APIError as e:
                print('[!] No info found for this IP')
                print(f'[!] {e}')
                print('No data found')
                print('---------Moving On-------')
                continue 
            print('------Preparing Next IP-------')

        
def main():
    parser = argparse.ArgumentParser(description='what it does')
    parser.add_argument('-f', '--ifile', help='File of ip addresses to scan')
    parser.add_argument('-c', '--cfile', help='CSV file to scan')

    args = parser.parse_args()

    if args.ifile:
        parse_ipfile_shodan(args.ifile)

    elif not args.cfile:
        print('[-] Usage: python3 get_plugxc2_info.py <<ip file>>')


if __name__ == '__main__':
    main()
