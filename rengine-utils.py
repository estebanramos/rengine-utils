import argparse, sys, urllib3
import authorize
from methods import target
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def error(parser,message):
        sys.stderr.write('error: %s\n' % message+'\n')
        parser.print_help()
        sys.exit(2)
        
parent_parser = argparse.ArgumentParser(add_help=False)
main_parser = argparse.ArgumentParser()
option_subparsers = main_parser.add_subparsers(title="options",dest="options")

auth_parser = option_subparsers.add_parser("authorize", help="",parents=[parent_parser])
target_parser = option_subparsers.add_parser("target", help="",parents=[parent_parser])


#Auth parsers
auth_parser.add_argument("-b", metavar="--base-url", action="store",help="URL (ie: https://localhost/)", default="https://localhost/",dest='base_url')
auth_parser.add_argument("-u", metavar="--user", action="store",help="ReNgine Username", dest='username')
auth_parser.add_argument("-p", metavar="--password", action="store",help="ReNgine Password", dest='password')
auth_parser.add_argument("-d", action="store_true",help="Deletes your session.  You should always do this once finished with the tool")


#Targets
target_action_subparser = target_parser.add_subparsers(title="target_action",dest="target_action_command")

target_list_subdomains_parser = target_action_subparser.add_parser("list-subdomains",help="List target found subdomains", parents=[parent_parser])
target_list_subdomains_parser.add_argument('-t', metavar='--target', dest='target_name', required=True)
target_list_subdomains_parser.add_argument('-p', metavar='--project', dest='project_name', required=True, help="ReNgine's Project Name")

target_list_endpoints_parser = target_action_subparser.add_parser("list-endpoints", help="List endpoints by target name or subdomain name")
target_list_endpoints_parser.add_argument('-t', metavar='--target', dest='target_name')
target_list_endpoints_parser.add_argument('-s', metavar='--subdomain', dest='subdomain_name')
target_list_endpoints_parser.add_argument('-p', metavar='--project', dest='project_name', required=True, help="ReNgine's Project Name")

target_list_vulnerabilities_parser = target_action_subparser.add_parser("list-vulnerabilities", help="List endpoints by target name or subdomain name")
target_list_vulnerabilities_parser.add_argument('-t', metavar='--target', dest='target_name')


target_list_parser = target_action_subparser.add_parser("list", help="List targets", parents=[parent_parser])
target_list_parser.add_argument("--clean", action="store_true", help="Simplify the output")

target_summary_parser = target_action_subparser.add_parser("generate-summary", help="Generates a summary of a domain subdomains and its vulnerabilities")
target_summary_parser.add_argument('-t', metavar='--target', dest='target_name', required=True)
target_summary_parser.add_argument('-p', metavar='--project', dest='project_name', required=True, help="ReNgine's Project Name")
target_summary_parser.add_argument('--clip', action="store_true", help='Copy the report to clipboard')



#Main section
try:
    args = main_parser.parse_args()
except Exception as e:
    print(e)

if(args.options == 'authorize'):
    if args.d:
        authorize.deleteSession()
    elif args.username and args.password:
        s = authorize.authorize(args.base_url, args.username, args.password)
    else:
        error(auth_parser, 'Missing parameters --username & --password')
else:
    s = authorize.getSession()


match args.options:
    case 'target':
        try:
            match args.target_action_command.lower():
                case 'list':
                    if args.clean:
                        target.listCleanTargets(s)
                    else:
                        target.listTargets(s)
                case 'list-subdomains':
                    if args.project_name:
                        target.listSubdomainsByTargetName(args.target_name, s, args.project_name)
                case 'list-endpoints':
                    if args.target_name:
                        target.listEndpointsByTargetName(args.target_name, s, args.project_name)
                    elif args.subdomain_name:
                        target.listEndpointsBySubdomainName(args.subdomain_name, s, args.project_name)
                    else:
                        error(target_list_endpoints_parser, 'Must specify one on the parameters -t or -s')
                case 'list-vulnerabilities':
                    target.listVulnerabilitiesByTargetName(args.target_name, s)
                case 'generate-summary':
                    target.generateSummaryByTargetName(args.target_name, s, args.project_name.lower(), args.clip)
        except Exception as e:
            print("An error as occurred")
            target_parser.print_help()
            