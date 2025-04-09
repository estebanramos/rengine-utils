import argparse, sys, urllib3, sys, traceback, pyperclip, argcomplete, signal, os, logging
import authorize
from methods import elastic_export, target, project, faraday_export, utils, mail_report, scans
from pwn import  *
from termcolor import colored

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def def_handler(sig, frame):
     print(colored(f"[!] Exiting...",'red'))
     sys.exit(1)

def error(parser,message):
        sys.stderr.write('error: %s\n' % message+'\n')
        parser.print_help()
        sys.exit(2)

signal.signal(signal.SIGINT, def_handler)

filter_choices = ['info', 'low', 'medium', 'high', 'critical']

parent_parser = argparse.ArgumentParser(add_help=False)
main_parser = argparse.ArgumentParser()
option_subparsers = main_parser.add_subparsers(title="options",dest="options")

auth_parser = option_subparsers.add_parser("authorize", help="",parents=[parent_parser])
target_parser = option_subparsers.add_parser("target", help="",parents=[parent_parser])
project_parser = option_subparsers.add_parser("project", help="", parents=[parent_parser])
scan_parser = option_subparsers.add_parser("scan", help="", parents=[parent_parser])

#Auth parsers
auth_parser.add_argument("-b", metavar="--base-url", action="store",help="URL (ie: https://localhost/)", default="https://localhost/",dest='base_url')
auth_parser.add_argument("-u", metavar="--user", action="store",help="ReNgine Username", dest='username')
auth_parser.add_argument("-p", metavar="--password", action="store",help="ReNgine Password", dest='password')
auth_parser.add_argument("-d", action="store_true",help="Deletes your session.  You should always do this once finished with the tool")

# Targets
target_action_subparser = target_parser.add_subparsers(title="target_action",dest="target_action_command")
## Target Subdomains
target_list_subdomains_parser = target_action_subparser.add_parser("list-subdomains",help="List target found subdomains", parents=[parent_parser])
target_list_subdomains_parser.add_argument('-t', metavar='--target', dest='target_name', required=True)
target_list_subdomains_parser.add_argument('-p', metavar='--project', dest='project_name', required=True, help="ReNgine's Project Name")
target_list_subdomains_parser.add_argument('--format',choices=['json', 'table'], default='table', help='Output format', dest='output_format')
## Target Endpoints
target_list_endpoints_parser = target_action_subparser.add_parser("list-endpoints", help="List endpoints by target name or subdomain name")
target_list_endpoints_parser.add_argument('-t', metavar='--target', dest='target_name')
target_list_endpoints_parser.add_argument('-s', metavar='--subdomain', dest='subdomain_name')
target_list_endpoints_parser.add_argument('-p', metavar='--project', dest='project_name', required=True, help="ReNgine's Project Name")
## Target Vulnerabilities
target_list_vulnerabilities_parser = target_action_subparser.add_parser("list-vulnerabilities", help="List endpoints by target name or subdomain name")
target_list_vulnerabilities_parser.add_argument('-t', metavar='--target', dest='target_name')
## List Targets
target_list_parser = target_action_subparser.add_parser("list", help="List targets", parents=[parent_parser])
target_list_parser.add_argument("--clean", action="store_true", help="Simplify the JSON output")
target_list_parser.add_argument('--format',choices=['json', 'table'], default='table', help='Output format', dest='output_format')
## Summary
target_summary_parser = target_action_subparser.add_parser("generate-summary", help="Generates a summary of a domain subdomains and its vulnerabilities")
target_summary_parser.add_argument('-t', metavar='--target', help='Target\'s (subdomain) name', dest='target_name', required=True)
target_summary_parser.add_argument('-p', metavar='--project', dest='project_name', required=True, help="ReNgine's Project Name")
target_summary_parser.add_argument('--show',action='store_true',help='Print the report to stdout')
target_summary_parser.add_argument('--clip', action="store_true", help='Copy the report to clipboard')
target_summary_parser.add_argument('-o', '--output', help='Copy the report to a file', dest='output_filename')
target_summary_parser.add_argument('--format', help="File output format, defaults to JSON", dest='file_output_format', choices=['json', 'csv'], default='json')
target_summary_parser.add_argument('-all', action="store_true", help='Generates a summary of all targets. Does not output to stdout for visibility reasons')
target_summary_parser.add_argument('--filter-vulns', help='Filter vulnerabilities severity in the report', type=utils.parse_filters, dest='vulns_filter_choices')
### Summary Export
target_summary_subparser = target_summary_parser.add_subparsers(title="export",dest="export_action")
#### Summary Elastic Export
target_summary_subparser_elastic = target_summary_subparser.add_parser('export-to-elastic',help='Export to Elasticsearch')
target_summary_subparser_elastic.add_argument('--host',dest="es_host")
target_summary_subparser_elastic.add_argument('--user','--username',dest='es_username')
target_summary_subparser_elastic.add_argument('--password',dest='es_password')
target_summary_subparser_elastic.add_argument('--index','-i',dest='es_index',default='rengine',help='Elasticsearch index in which store the data/report')
#### Summary Faraday Export
target_summary_subparser_faraday = target_summary_subparser.add_parser('export-to-faraday', help='Export to faraday')
target_summary_subparser_faraday.add_argument('--host', dest="faraday_host", required=True)
target_summary_subparser_faraday.add_argument('--user','--username',dest='faraday_username', required=True)
target_summary_subparser_faraday.add_argument('--password',dest='faraday_password', required=True)
target_summary_subparser_faraday.add_argument('-w', '--workspace', help='Faraday workspace', dest='faraday_workspace', required=True)

#Projects
project_parser.add_argument("-l", "--list", action="store_true", help="List the projects")
project_parser.add_argument("-df", action="store_true", help="Returns the default project for the User logged")

#Scan
scan_parser.add_argument("-t", help="Target to scan", dest="target_name", required=True)
scan_parser.add_argument("-p", help="ReNgine's Project Name", required=True, dest='project_name')

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
    if(authorize.getSession()): 
        s = authorize.getSession()
    else:
        exit()
      
match args.options:
    case 'target':
        try:
            match args.target_action_command.lower():
                case 'list':
                    match args.output_format:
                        case 'json':
                            if args.clean: target.listCleanTargets(s)
                            else: target.listTargets(s)
                        case 'table':
                            target.listTargetsTable(s)
                case 'list-subdomains':
                    if args.project_name:
                        match args.output_format:
                            case 'json':
                                target.listSubdomainsByTargetNameJSON(args.target_name, s, args.project_name)
                            case 'table':
                                target.listSubdomainsByTargetNameTable(args.target_name, s, args.project_name)
                case 'list-endpoints':
                    if args.target_name:
                        target.listEndpointsByTargetName(args.target_name, s, args.project_name)
                    elif args.subdomain_name:
                        target.listEndpointsBySubdomainName(args.subdomain_name, s, args.project_name)
                    else:
                        error(target_list_endpoints_parser, 'Must specify one on the parameters -t or -s')
                case 'list-vulnerabilities':
                    if(target.TargetExists(args.target_name, s)):
                        #target.listVulnerabilitiesByTargetName(args.target_name, s)
                        vulns = target.getVulnerabilitiesByTargetName(args.target_name,s)
                        pyperclip.copy(str(vulns))
                        filtered = target.removeAndJoinDuplicateVulns(vulns)
                        pyperclip.copy(str(filtered))
                    else:
                        target.listVulnerabilitiesBySubdomain(args.target_name, s)
                case 'generate-summary':
                    if args.export_action:
                        export = True
                    else: export = False

                    if args.all:
                        report = target.generateGeneralSummary(s, args.project_name.lower(), export, args.vulns_filter_choices)
                    else:
                        report = target.generateSummaryByTargetName(args.target_name, s, args.project_name.lower(), args.clip, args.output_filename, args.show, args.vulns_filter_choices)
                    match args.export_action:
                        case 'export-to-elastic':
                            try:
                                es = elastic_export.initialize(args.es_host, args.es_username, args.es_password)
                                if es:
                                    if 'subdomain' in report: 
                                        elastic_export.indexDocument(es, args.es_index, report)
                                    else:
                                        for mini_r in report:
                                            elastic_export.indexDocument(es, args.es_index, mini_r)
                                    print("Exported report to Elasticsearch")                               
                                else: print("Failed to Connect to Elasticsearch instance")
                            except:
                                print("Failed to send report")
                                traceback.print_exc()
                        case 'export-to-faraday':
                            session = faraday_export.authenticate(args.faraday_host, args.faraday_username, args.faraday_password)
                            for r in report:
                                if 'subdomain' in r:
                                    try:
                                        faraday_export.create_vuln(session, args.faraday_host, args.faraday_workspace, r['subdomain'])
                                    except:
                                        print("Error exporting vulnerabilities to Faraday")
                                        traceback.print_exc()
                                else:
                                    try:
                                        for mini_r in r:
                                            faraday_export.create_vuln(session, args.faraday_host, args.faraday_workspace, mini_r['subdomain'])
                                    except:
                                        print("Error exporting vulnerabilities to Faraday")
                                        traceback.print_exc()
                case _:
                    target_parser.print_help()
        except AttributeError:
            target_parser.print_help()
            traceback.print_exc()
        except Exception as e:
            print("An error as occurred")
            traceback.print_exc()
    case 'project':
        if args.list:
            print("Projects listed in Rengine instance: ")
            projects = project.listProjects(s, project.getDefaultProject(s))
            for project in projects:
                print(project)
        elif args.df:
            print(f"Default project for current session: {project.getDefaultProject(s)}")
        else:
            project_parser.print_help()
    case 'scan':
        print(args)
        if args.project_name and args.target_name:
            print("Starting Scan...")
            scans.run_scan(s, args.target_name, args.project_name)

            