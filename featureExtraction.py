from os import popen
from typing import List, Tuple, Union
from numpy.lib.function_base import average
import tldextract
import socket
from scapy.all import IP, traceroute
import ipwhois
from urllib.parse import urlparse
import pycountry
from bs4 import BeautifulSoup
import requests

def getGeoLoc(ip: str):
    GEO_IP_API = f'https://ipinfo.io/{ip}/json'
    req = requests.get(GEO_IP_API)
    try:
        resp = req.json()
        country = pycountry.countries.lookup(resp['country'])
        try:
            name = country.common_name
        except:
            name = country.name
        print(f"Geo Location: {name}")
        return name
    except Exception as E:
        print(E.args)
        raise

def getHTTPS(url: str)->bool:
    if urlparse(url).scheme == 'https':
        print(f"https: true")
        return 'https'
    else:
        print(f"https: false")
        return 'http'

def getUrlLen(url: str)->int:
    return len(url)

def getIP(url: str)->str:
    ip = socket.gethostbyname_ex(urlparse(url).hostname)
    print(f"ip: {ip[2][0]}")
    return ip[2][0]

def getTLD(url: str)-> str:
    tld = tldextract.extract(url).domain
    print(f"tld: {tld}")
    return tld

def getwhois(ip:str)-> str:
    if ipwhois.IPWhois(ip).lookup_rdap()['asn']:
        print("whois: complete")
        return "complete"
    else:
        print("whois: incomplete")
        return 'incomplete'

def getContentInfo(url:str)-> dict:
    html = requests.get(url).text
    soup = BeautifulSoup(html, features="html.parser")
    content = len(soup.text)
    js=0
    obfusJS=0
    for element in soup.findAll("script"):
        string = element.string
        if string is None:
            src = element.get("src")
            print(src)
            if src[0]!='/':
                string = requests.get(element.get("src")).text
            else:
                string = requests.get(url+element.get("src")).text
        if "eval" not in string:
            js += len(string)
        else:
            obfusJS += len(string)

    rt = {"js_len": js, "js_obf_len": obfusJS, "content": content}
    for arg in rt:
        print(f"{arg}: {rt[arg]}")
    return rt

def getHopCount(url:str)->float:
    furl = tldextract.extract(url).fqdn
    print("Sending requests for hop count. This might take a while")
    result, _ = traceroute(furl, maxttl=32, verbose=0, timeout=10)
    hopCount = (average([snd[IP].ttl for snd, _ in result[IP]]))
    print(f"hopCount: {hopCount}")
    return hopCount


def extractAllFeatures(url: str) -> dict:
    ip = getIP(url)
    return {
        "url": url,
        "url_len": len(url),
        "ip_add": ip,
        "geo_loc": getGeoLoc(ip),
        "tld": getTLD(url),
        "who_is": getwhois(ip),
        "https": getHTTPS(url),
        **getContentInfo(url),
        "hopCount": getHopCount(url)
    }

if __name__=="__main__":
    url = input("Enter URL\n").strip()
    print(extractAllFeatures(url))
