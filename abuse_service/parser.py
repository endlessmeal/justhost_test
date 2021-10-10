import argparse
import spamhaus

parser = argparse.ArgumentParser(description="Parse the Spamhaus SBL for your domain")
parser.add_argument("-d", "--domain", help="The domain you want to query")
parser.add_argument("-i", "--ip", help="The IPv4 you want to query")
args = parser.parse_args()

if args.domain:
    print("Start parsing...")
    for rec in spamhaus.check_listings(args.domain):
        print('ref: {}\nlink: {}\ntimestamp: {}\nip addr: {}\ndesc: {}\ndomains: {}\n'.format(
                rec['ref'],
                rec['link'],
                rec['timestamp'],
                rec['ip_address'],
                rec['description'],
                rec['domains']
            )
        )
    print("End parsing...")
elif args.ip:
    spamhaus.check_addr_in_lists(args.ip)
else:
    parser.print_help()
