import http.client
import json
import time

import csv 

import os
from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import Intf
from mininet.node import Controller
from mininet.node import RemoteController, OVSSwitch

#class NetworkTopo( Topo ):
    # Builds network topology
#    def build( self, **_opts ):
#
#        s1 = self.addSwitch ( 's1', failMode='standalone' )
#        s2 = self.addSwitch ( 's2', failMode='standalone' )
#        s3 = self.addSwitch ( 's3', failMode='standalone' )
#        
#
#        # Adding hosts
#        h1 = self.addHost( 'h1', ip='192.168.0.1/28' )
#        h2 = self.addHost( 'h2', ip='192.168.0.2/28' )
#        h3 = self.addHost( 'h3', ip='192.168.0.3/28' )
#        h4 = self.addHost( 'h4', ip='192.168.0.9/28' )
#        #d5 = self.addHost( 'h5', ip='192.168.0.10/28' )
#        #d6 = self.addHost( 'h6', ip='192.168.0.11/28' )
#        
#
#        # Connecting hosts to switches
#        for d, s in [ (h1, s2), (h2, s2), (h3, s3),(h4, s3),(s1,s2),(s1,s3)]:
#            self.addLink( d, s )
        




class StaticEntryPusher(object):
    def __init__(self, server):
        self.server = server
    def get(self, data, url):
        ret = self.rest_call({}, 'GET', url)
        return json.loads(ret[2])
    def set(self, data, url):
        ret = self.rest_call(data, 'POST', url)
        return ret[0] == 200
    def put(self, data, url):
        ret = self.rest_call(data, 'PUT', url)
        return ret[0] == 200
    def remove(self, objtype, data, url):
        ret = self.rest_call(data, 'DELETE', url)
        return ret[0] == 200
    def rest_call(self, data, action, url):
        path = ""
        if(url == 1):
            path = '/wm/staticflowpusher/json'
        elif(url == 2):
            path = '/wm/acl/rules/json'
        elif(url == 3):
            path = '/wm/firewall/module/enable/json'
        else:
            path = '/wm/firewall/rules/json'
        headers = {
                'Content-type': 'application/json',
                'Accept': 'application/json',
                }
        body = json.dumps(data)
        print(body)
        print(action)
        print(path)
        conn = http.client.HTTPConnection(self.server, 8080)
        if (url==3):
            conn.request(action, path)
        else:
            conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        print(body)
        print(ret)

        conn.close()
        return ret
pusher = StaticEntryPusher('localhost')
flow1 = {
        'switch':"00:00:00:00:00:00:00:01",
        "name":"flow_mod_1",
        "cookie":"0",
        "priority":"32768",
        "in_port":"1",
        "active":"true",
        "actions":"output=flood"
        }
flow2 = {
        'switch':"00:00:00:00:00:00:00:01",
        "name":"flow_mod_2",
        "cookie":"0",
        "priority":"32768",
        "in_port":"2",
        "active":"true",
        "actions":"output=flood"
        }

flow3 = {
        "src-ip":"10.0.0.1/32",
        #"dst-ip":"10.0.0.4/32",
        "action":"deny"
        }

allowflow= {
        "src-ip": "10.0.0.2/32",
        "dst-ip": "10.0.0.7/32"
        }

denyflow= {
        "src-mac": "00:00:00:00:00:02",
        "dst-mac": "00:00:00:00:00:01",
        "action": "DENY"
        }

def run():

#    topo = NetworkTopo()
    
#    net = Mininet( topo=topo, controller=lambda name: RemoteController( name, ip='127.0.0.1' ),switch=OVSSwitch, autoSetMacs=True)
    tree4 = TreeTopo(depth=3,fanout=2)
    net = Mininet( topo=tree4, controller=lambda name: RemoteController( name, ip='127.0.0.1' ),switch=OVSSwitch, autoSetMacs=True)
    net.start()
    #CLI( net )
    secflow = None
    #pusher.set(flow1, 1)
    #pusher.set(flow2, 1)
    pusher.put(secflow,3)
    #pusher.set(flow3, 2)
    #pusher.set(allowflow, 4)
    #pusher.set(denyflow, 4)
    #time.sleep(15)
    print("-------------")
    print("starting firewall part")
    with open('ipblocklist_aggressive.csv') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                print(f'Column names are {", ".join(row)}')
                line_count += 1
            else:
                line_count += 1
                denyflow2 = denyflow
                denyflow["dst-ip"]=row[1]
                pusher.set(denyflow2,4)
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
    



