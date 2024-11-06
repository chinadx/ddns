# -*- coding: utf-8 -*-
import hashlib
import hmac
import json
import os
import time
import requests
from datetime import datetime

# 设置工作目录为脚本所在目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 从配置文件读取密钥
def load_config(config_file='config.json'):
    with open(config_file, 'r') as f:
        config = json.load(f)
    return (config['secret_id'],
            config['secret_key'],
            config['domain'],
            config['sub_domain']
            )


# 获取公网ip
def get_public_ip():
    try:
        response = requests.get('http://ipinfo.io/ip')
        if response.status_code == 200:
            return response.text.strip()  # strip to remove any extra whitespace
        else:
            return "Failed to get IP"
    except requests.exceptions.RequestException as e:
        return f"An error occurred: {e}"


# 签名计算函数
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


# 构建请求并发送
def send_request(secret_id, secret_key, action, params):
    service = "dnspod"
    host = "dnspod.tencentcloudapi.com"
    endpoint = "https://" + host
    version = "2021-03-23"
    algorithm = "TC3-HMAC-SHA256"
    timestamp = int(time.time())
    date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")

    # 拼接规范请求串
    http_request_method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    ct = "application/json; charset=utf-8"
    payload = json.dumps(params)
    canonical_headers = f"content-type:{ct}\nhost:{host}\nx-tc-action:{action.lower()}\n"
    signed_headers = "content-type;host;x-tc-action"
    hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = (http_request_method + "\n" +
                         canonical_uri + "\n" +
                         canonical_querystring + "\n" +
                         canonical_headers + "\n" +
                         signed_headers + "\n" +
                         hashed_request_payload)

    # 拼接待签名字符串
    credential_scope = date + "/" + service + "/" + "tc3_request"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = (algorithm + "\n" +
                      str(timestamp) + "\n" +
                      credential_scope + "\n" +
                      hashed_canonical_request)

    # 计算签名
    secret_date = sign(("TC3" + secret_key).encode("utf-8"), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    # 拼接 Authorization
    authorization = (algorithm + " " +
                     "Credential=" + secret_id + "/" + credential_scope + ", " +
                     "SignedHeaders=" + signed_headers + ", " +
                     "Signature=" + signature)

    # 请求头
    headers = {
        "Authorization": authorization,
        "Content-Type": ct,
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version
    }

    # 发送POST请求
    response = requests.post(endpoint, headers=headers, data=payload)

    # 打印响应
    if response.status_code == 200:
        print("action=", action, "response=", response.json())
        return response.json()  # 直接返回响应数据
    else:
        print("Request Failed with status code: ", response.status_code)
        print(response.text)
        return None


# 获取 DNS 记录列表并过滤出特定记录
def get_record_list(secret_id, secret_key, domain, sub_domain):
    params = {
        "Domain": domain
    }

    # 调用 DescribeRecordList API
    response_data = send_request(secret_id, secret_key, "DescribeRecordList", params)

    if response_data and 'Response' in response_data:
        record_list = response_data['Response'].get('RecordList', [])
        # 过滤出Value等于sub_domain的记录
        remote_records = [(record['RecordId'], record['Value']) for record in record_list if
                          record['Name'] == sub_domain]
        return remote_records
    else:
        print("Failed to retrieve record list.")
        return []


# 更新 DNS 记录
def update_record(secret_id, secret_key, domain, sub_domain, record_id, value):
    params = {
        "Domain": domain,
        "SubDomain": sub_domain,
        "RecordType": "A",
        "RecordLine": "默认",
        "Value": value,
        "RecordId": record_id
    }

    # 调用 ModifyRecord API
    response_data = send_request(secret_id, secret_key, "ModifyRecord", params)

    if response_data:
        print("DNS Record Updated Successfully!")
    else:
        print("Failed to update DNS record.")


def main():
    # 从配置文件读取密钥
    secret_id, secret_key, domain, sub_domain = load_config()
    public_ip = get_public_ip()  # 获取公网IP
    print("Public IP: ", public_ip)

    # 第一步：检查 DNS 记录是否需要更新
    remote_records = get_record_list(secret_id, secret_key, domain, sub_domain)

    if remote_records:
        if any(record[1] == public_ip for record in remote_records):
            print("IP not changed")
            return

        # 第二步：更新 DNS 记录
        record_id, old_value = remote_records[0]  # 选取第一个匹配的记录
        print(f"Updating record {record_id} from {old_value} to {public_ip}")
        update_record(secret_id, secret_key, domain, sub_domain, record_id, public_ip)
    else:
        print(f"No matching record found for subdomain {sub_domain}.")


if __name__ == "__main__":
    main()
