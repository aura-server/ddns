#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from __future__ import print_function
import json
import os
import re
import sys
from datetime import datetime, timedelta

from aliyunsdkalidns.request.v20150109 import UpdateDomainRecordRequest, DescribeDomainRecordsRequest, AddDomainRecordRequest
from aliyunsdkcore import client

records_example = '''
[
    {
         u'DomainName': u'aura.ren',
         u'Line': u'default',
         u'Locked': False,
         u'RR': u'nas',
         u'RecordId': u'4056406460896256',
         u'Status': u'ENABLE',
         u'TTL': 600,
         u'Type': u'CNAME',
         u'Value': u'home.aura.ren',
         u'Weight': 1
     },
     {
         u'DomainName': u'aura.ren',
         u'Line': u'default',
         u'Locked': False,
         u'RR': u'g',
         u'RecordId': u'4056158942827520',
         u'Status': u'ENABLE',
         u'TTL': 600,
         u'Type': u'A',
         u'Value': u'39.104.203.229',
         u'Weight': 1
     }
 ]
 '''


class AliDDNS:
    def __init__(self, dns_domain, access_key_id, access_key_secret):
        self.dns_domain = dns_domain
        self.dns_format = 'json'
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.records_cache = None
        self.records_cache_time = None

    def do_action(self, request):
        clt = client.AcsClient(self.access_key_id, self.access_key_secret, 'cn-hangzhou')
        result = clt.do_action_with_exception(request)
        return json.loads(result)

    def get_records(self):
        if self.records_cache and self.records_cache_time and datetime.now() - self.records_cache_time < timedelta(minutes=1):
            return self.records_cache
        print('get records')
        request = DescribeDomainRecordsRequest.DescribeDomainRecordsRequest()
        request.set_DomainName(self.dns_domain)
        request.set_accept_format(self.dns_format)
        result = self.do_action(request)
        result = result['DomainRecords']['Record']
        self.records_cache = result
        self.records_cache_time = datetime.now()
        return result

    def update_dns(self, dns_rr, dns_value, dns_type, dns_record_id, dns_ttl):
        print('update_dns')
        request = UpdateDomainRecordRequest.UpdateDomainRecordRequest()
        request.set_RR(dns_rr)
        request.set_Type(dns_type)
        request.set_Value(dns_value)
        request.set_RecordId(dns_record_id)
        request.set_TTL(dns_ttl)
        request.set_accept_format(self.dns_format)
        result = self.do_action(request)
        self.records_cache_time = None
        print('{}.{} -> {}'.format(dns_rr, self.dns_domain, dns_value))
        return result

    def add_dns(self, dns_rr, dns_value, dns_type, dns_ttl, dns_domain):
        print('add_dns')
        request = AddDomainRecordRequest.AddDomainRecordRequest()
        request.set_DomainName(dns_domain)
        request.set_RR(dns_rr)
        request.set_Type(dns_type)
        request.set_Value(dns_value)
        request.set_TTL(dns_ttl)
        result = self.do_action(request)
        self.records_cache_time = None
        print('{}.{} -> {}'.format(dns_rr, dns_domain, dns_value))
        return result

    def ddns(self, rr, ip):
        records = self.get_records()
        rec = [r for r in records if r['Type'] == 'A' and r['RR'] == rr]
        if len(rec):
            rec = rec[0]
            old_ip = rec['Value']
            record_id = rec['RecordId']
            if ip != old_ip:
                self.update_dns(dns_rr=rr, dns_value=ip, dns_type='A', dns_record_id=record_id, dns_ttl='600')
        else:
            self.add_dns(dns_rr=rr, dns_value=ip, dns_type='A', dns_ttl='600', dns_domain=self.dns_domain)


def read_csv(file_name):
    config = {}

    with open(file_name, 'r') as f:
        lines = f.readlines()
    lines = [l.strip().split(',') for l in lines]
    for i, x in enumerate(lines[0]):
        config[x] = lines[1][i]

    return config


if __name__ == '__main__':
    config = read_csv('account.csv')
    alidns = AliDDNS('aura.ren', config['AccessKeyId'], config['AccessKeySecret'])
    recs = alidns.get_records()
    print(recs)
    # alidns.ddns('test','192.168.1.1')
