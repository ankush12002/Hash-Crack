#!/usr/bin/env python3
import re
import os
import requests
import argparse
import concurrent.futures

parser = argparse.ArgumentParser()
parser.add_argument('-s', help='hash', dest='hash')
parser.add_argument('-f', help='file containing hashes', dest='file')
parser.add_argument('-d', help='directory containing hashes', dest='dir')
parser.add_argument('-t', help='number of threads', dest='threads', type=int)
args = parser.parse_args()

# Colors and formatting
end = '\033[0m'
red = '\033[91m'
green = '\033[92m'
white = '\033[97m'
dgreen = '\033[32m'
yellow = '\033[93m'
back = '\033[7;91m'
run = '\033[97m[~]\033[0m'
que = '\033[94m[?]\033[0m'
bad = '\033[91m[-]\033[0m'
info = '\033[93m[!]\033[0m'
good = '\033[92m[+]\033[0m'

cwd = os.getcwd()
directory = args.dir
file = args.file
thread_count = args.threads or 4

if directory and directory[-1] == '/':
    directory = directory[:-1]

def alpha(hashvalue, hashtype):
    return False

def beta(hashvalue, hashtype):
    response = requests.get('https://hashtoolkit.com/reverse-hash/?hash=' + hashvalue).text
    match = re.search(r'/generate-hash/\?text=(.*?)"', response)
    return match.group(1) if match else False

def gamma(hashvalue, hashtype):
    try:
        response = requests.get(f'https://www.nitrxgen.net/md5db/{hashvalue}', verify=True).text
        return response if response else False
    except requests.exceptions.RequestException:
        return False

def delta(hashvalue, hashtype):
    return False

def theta(hashvalue, hashtype):
    response = requests.get(
        f'https://md5decrypt.net/Api/api.php?hash={hashvalue}&hash_type={hashtype}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728'
    ).text
    return response if len(response) != 0 else False

# Fix the escape sequence warning by using a raw string (r'') or properly escaping the backslashes
print(r'''
  _    _           _            _____                _    
 | |  | |         | |          / ____|              | |   
 | |__| | __ _ ___| |__ ______| |     _ __ __ _  ___| | __
 |  __  |/ _` / __| '_ \______| |    | '__/ _` |/ __| |/ /
 | |  | | (_| \__ \ | | |     | |____| | | (_| | (__|   < 
 |_|  |_|\__,_|___/_| |_|      \_____|_|  \__,_|\___|_|\_\
                                                          
                                                          
\033[0m\n''')


md5 = [gamma, alpha, beta, theta, delta]
sha1 = [alpha, beta, theta, delta]
sha256 = [alpha, beta, theta]
sha384 = [alpha, beta, theta]
sha512 = [alpha, beta, theta]

def crack(hashvalue):
    result = False
    if len(hashvalue) == 32:
        if not file:
            print(f'{info} Hash function : MD5')
        for api in md5:
            r = api(hashvalue, 'md5')
            if r:
                return r
    elif len(hashvalue) == 40:
        if not file:
            print(f'{info} Hash function : SHA1')
        for api in sha1:
            r = api(hashvalue, 'sha1')
            if r:
                return r
    elif len(hashvalue) == 64:
        if not file:
            print(f'{info} Hash function : SHA-256')
        for api in sha256:
            r = api(hashvalue, 'sha256')
            if r:
                return r
    elif len(hashvalue) == 96:
        if not file:
            print(f'{info} Hash function : SHA-384')
        for api in sha384:
            r = api(hashvalue, 'sha384')
            if r:
                return r
    elif len(hashvalue) == 128:
        if not file:
            print(f'{info} Hash function : SHA-512')
        for api in sha512:
            r = api(hashvalue, 'sha512')
            if r:
                return r
    else:
        if not file:
            print(f'{bad} This hash type is not supported.')
            quit()
        else:
            return False

result = {}

def threaded(hashvalue):
    resp = crack(hashvalue)
    if resp:
        print(hashvalue + ' : ' + resp)
        result[hashvalue] = resp

def grepper(directory):
    # Fix the invalid escape sequence issue
    os.system(f'''grep -Pr "[a-f0-9]{{128}}|[a-f0-9]{{96}}|[a-f0-9]{{64}}|[a-f0-9]{{40}}|[a-f0-9]{{32}}" {directory} --exclude=\*.{{png,jpg,jpeg,mp3,mp4,zip,gz}} |
        grep -Po "[a-f0-9]{{128}}|[a-f0-9]{{96}}|[a-f0-9]{{64}}|[a-f0-9]{{40}}|[a-f0-9]{{32}}" >> {cwd}/{directory.split('/')[-1]}.txt''')
    print(f'{info} Results saved in {directory.split("/")[-1]}.txt')

def miner(file):
    lines = []
    found = set()
    with open(file, 'r') as f:
        for line in f:
            lines.append(line.strip('\n'))
    for line in lines:
        matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
        if matches:
            for match in matches:
                found.add(match)
    print(f'{info} Hashes found: {len(found)}')
    threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=thread_count)
    futures = (threadpool.submit(threaded, hashvalue) for hashvalue in found)
    for i, _ in enumerate(concurrent.futures.as_completed(futures)):
        if i + 1 == len(found) or (i + 1) % thread_count == 0:
            print(f'{info} Progress: {i + 1}/{len(found)}', end='\r')

def single(args):
    result = crack(args.hash)
    if result:
        print(result)
    else:
        print(f'{bad} Hash was not found in any database.')

if directory:
    try:
        grepper(directory)
    except KeyboardInterrupt:
        pass

elif file:
    try:
        miner(file)
    except KeyboardInterrupt:
        pass
    with open(f'cracked-{file.split("/")[-1]}', 'w+') as f:
        for hashvalue, cracked in result.items():
            f.write(hashvalue + ':' + cracked + '\n')
    print(f'{info} Results saved in cracked-{file.split("/")[-1]}')

elif args.hash:
    single(args)
