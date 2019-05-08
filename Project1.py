''' 1st Exercise in Big Data Management
    Students : Mitsou Alexandros, Isidoros Koutsoumpos'''

import os
import re
import sys
import hashlib
import pandas as pd
from random import randint
from random import getrandbits
from ipaddress import IPv4Address, IPv6Address
import collections


class Node():
    def __init__(self, ip_address,port,id):
        self.ip = ip_address
        self.port = port
        self.id = id
        self.finger_table = []

    def node_info(self):
        return 'ID: {0}, IP: {1}, PORT: {2}'.format(self.id, self.ip, self.port)


def createIP(version):
    if version == 4:
        bits = getrandbits(32) # generates an integer with 32 random bits
        addr = IPv4Address(bits) # instances an IPv4Address object from those bits
        addr_str = str(addr) # get the IPv4Address object's string representation
    elif version == 6:
        bits = getrandbits(128) # generates an integer with 128 random bits
        addr = IPv6Address(bits) # instances an IPv6Address object from those bits
        # .compressed contains the short version of the IPv6 address
        # str(addr) always returns the short address
        # .exploded is the opposite of this, always returning the full address with all-zero groups and so on
        addr_str = addr.compressed
    return(addr_str)

def createPort():
    """
    According to RFC 793, the port is a 16 bit unsigned int.
    This means the range is 0 - 65535.
    ports 0 - 1023 are generally reserved for specific purposes
    Well-known ports: 0 to 1023 (used for system services e.g. HTTP, FTP, SSH, DHCP ...)
    Dynamic/private ports: 49152 to 65535.
    So a node's port should be within the range (1024-65535)
    """

    starting_interval = 0
    ending_interval = 65535

    port = randint(starting_interval, ending_interval)
    return (port)

def hashing_info(string):#KEY HASHING FUNCTION

    """
    Use MD5 hash to hash a string, convert it to integer and shift right (128 - m) places
    Why shifting right (128 - m) places:
        - Shifting right m places equals to dividing 2^m.
        - Given m and a value 2^128, in order to find 2^m, need to need to divide 2^128 by 2^(128-m)
    :param input_string: String
    :return: String
    """

    nodeInfo = string.encode('utf-8')

    #md5 -> 2^7 = 128 bits
    hash_object = hashlib.md5()
    hash_object.update(nodeInfo)

    tmp = hash_object.hexdigest()
    tmp = int(tmp,16)

    result = tmp >> (128-16)
    return (result)

def parseApps(csv_file):
    #regular expression to remove emojis from app names
    emoji = re.compile("["
                           u"\U0001F600-\U0001F64F"  # emoticons
                           u"\U0001F300-\U0001F5FF"  # symbols & pictographs
                           u"\U0001F680-\U0001F6FF"  # transport & map symbols
                           u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
                           "]+", flags=re.UNICODE)

    #read apps from appstore and save it in python list
    appName = []
    df = pd.read_csv(csv_file)
    tmp = df.App.tolist()

    appName = [emoji.sub(r'', elem) for elem in tmp]

    return (appName)



def main():
    print("Type number of nodes to be created!")
    # N is the number of nodes to be created
    N = input()
    # Casting N to integer to use it in for loop
    N = int(N)

    # Chord_instance is a list
    chord_instance = {}

    # Getting googleplaystore.csv file to be parsed
    path_to_csv = os.getcwd()
    path_to_csv = os.path.join(path_to_csv, "googleplaystore.csv")
    # print(path_to_csv)

    # List containing apps to be hashed and placed at the appropriate nodes
    appNames = parseApps(path_to_csv)
    # print(appNames)
    # List containing the hashed app names to IDs
    apps = []
    # Getting app IDs and saving them into apps list
    apps = [hashing_info(elem) for elem in appNames]

    table_finger = {}

    for i in range(N):
        ip_address = createIP(4)
        port = createPort()

        # Node's id = (ipaddress,port) pair
        nodeID = hashing_info("{0}:{1}".format(ip_address, port))
        print("NodeId:",nodeID,"Node ip address:",ip_address, "Node port:",port)

        # Create Node Object
        node = Node(ip_address, port, nodeID)
        chord_instance[node.id] = [node.ip,node.port]

        # chord_instance.append(node)
        #print(node.node_info())
        print("-------")
    # chord_instance = collections.OrderedDict(sorted(chord_instance.items()))
    print(list(chord_instance.keys())[0])

        # """
        # #Gather nodes
        # #Sort Nodes by ID
        # #Place Node into Chord Ring at the appropriate position
        # #Create Node's finger table
        # """

main()