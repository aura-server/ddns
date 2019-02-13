from datetime import datetime
import requests
import random
import hmac
import sys
import binascii
import hashlib
import base64
import urllib


def sign(message, key):
    key = bytes(key, 'UTF-8')
    message = bytes(message, 'UTF-8')

    digester = hmac.new(key, message, hashlib.sha1)
    digester = hmac.new(key, message, hashlib.sha1)
    # signature1 = digester.hexdigest()
    signature1 = digester.digest()
    print(signature1)

    # signature2 = base64.urlsafe_b64encode(bytes(signature1, 'UTF-8'))
    signature2 = base64.urlsafe_b64encode(signature1)
    print(signature2)

    return str(signature2, 'UTF-8')


# def sign(secretKey, signStr, signMethod):
#     if sys.version_info[0] > 2:
#         signStr = signStr.encode("utf-8")
#         secretKey = secretKey.encode("utf-8")
#
#     # 根据参数中的signMethod来选择加密方式
#     if signMethod == 'HmacSHA256':
#         digestmod = hashlib.sha256
#     elif signMethod == 'HmacSHA1':
#         digestmod = hashlib.sha1
#
#     # 完成加密，生成加密后的数据
#     hashed = hmac.new(secretKey, signStr, digestmod)
#     base64 = binascii.b2a_base64(hashed.digest())[:-1]
#
#     if sys.version_info[0] > 2:
#         base64 = base64.decode()
#
#     return base64

def dictToStr(dictData):
    tempList = []
    for eveKey, eveValue in dictData.items():
        tempList.append(str(eveKey) + "=" + str(eveValue))
    return "&".join(tempList)


class QCloudAPIClass:
    UserName = ''
    SecretId = ''
    SecretKey = ''
    API_BASE = ''
    API_ROUTE = '/v2/index.php'

    def _sign_request(self, method, data):
        req_str = '&'.join([k + '=' + str(v) for k, v in sorted(data.items())])
        sgn_origin = method + self.API_BASE + self.API_ROUTE + '?' + req_str
        sgn = sign(sgn_origin, self.SecretKey)
        data.update({
            'Signature': sgn,
        })
        data = {k: v for k, v in sorted(data.items())}
        return data

    def _api_request(self, data, method='GET'):
        _data = data
        data = {
            # 'Region': 'ap-beijing',  # ?
            'Timestamp': str(int(datetime.now().timestamp())),
            'Nonce': random.randint(0, 100000),
            'SecretId': self.SecretId,
            'SignatureMethod': 'HmacSHA1',
        }
        data.update(_data)
        if 'Action' not in data:
            raise Exception('action needed')

        url = 'https://' + self.API_BASE + self.API_ROUTE
        data = self._sign_request(method, data)
        print(data)
        print(url)
        res = getattr(requests, method.lower())(url, data=data)
        print(res.text)
        res = res.json()
        if 'code' not in res or res['code'] != 0:
            print(res)
            raise Exception('API Error')
        return res

    def recordModify(self):
        recordType = 'A'
        value = '1.1.1.1'

        self.run({
            'Action': 'RecordModify',
            'domain': 'aura.ren',
            'recordId': '?',
            'subDomain': 'home',
            'recordType': recordType,
            'recordLine': '默认',
            'value': value,
        })

    def recordList(self):
        res = self._api_request(method='GET', data={
            'Action': 'DescribeRegions',
            # 'Region': 'gz',
            # 'domain': 'aura.ren',
            'offset': 0,
            'length': 10,
        })
        print(res)

    def __init__(self, csv_file, api_base=None):
        if api_base:
            self.API_BASE = api_base

        if not self.API_BASE:
            raise Exception('api_base invalid')

        with open(csv_file, 'r') as f:
            ll = f.readlines()
            self.UserName, self.SecretId, self.SecretKey = ll[1].split(',')
        if not self.UserName or not self.SecretKey or not self.SecretKey:
            raise Exception('invalid csv file')


CNSAPI = QCloudAPIClass(api_base='cvm.api.qcloud.com', csv_file='account.csv')


def main():
    print(CNSAPI.recordList())


if __name__ == '__main__':
    main()
