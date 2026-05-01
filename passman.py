import argparse
import sys
from db import Database
from crypto import Crypto

def main():
    parser = argparse.ArgumentParser(description='CLI Password Manager')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize password manager with master password')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new password')
    add_parser.add_argument('service', help='Service name')
    add_parser.add_argument('password', help='Password')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get password for a service')
    get_parser.add_argument('service', help='Service name')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all services')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update password for a service')
    update_parser.add_argument('service', help='Service name')
    update_parser.add_argument('password', help='New password')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a password entry')
    delete_parser.add_argument('service', help='Service name')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    db = Database()
    
    if args.command == 'init':
        db.init_master_password()
    
    elif args.command == 'add':
        db.add_password(args.service, args.password)
    
    elif args.command == 'get':
        password = db.get_password(args.service)
        if password:
            print(f"Password for {args.service}: {password}")
        else:
            print(f"No password found for {args.service}")
    
    elif args.command == 'list':
        services = db.list_services()
        if services:
            print("Stored services:")
            for service in services:
                print(f"  - {service}")
        else:
            print("No passwords stored yet")
    
    elif args.command == 'update':
        db.update_password(args.service, args.password)
    
    elif args.command == 'delete':
        db.delete_password(args.service)

if __name__ == '__main__':
    main()
