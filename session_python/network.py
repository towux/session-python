import time
import random
import requests
import binascii
import urllib3
from typing import List, Dict, Any, Union, Optional
from urllib.parse import urlparse

# Suppress self-signed certificate warnings for storage node connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Seeds list
SEEDS = [
    {"url": "seed1.getsession.org"},
    {"url": "seed2.getsession.org"},
    {"url": "seed3.getsession.org"}
]

class NetworkError(Exception):
    pass

class SnodeFetchError(NetworkError):
    pass

class SnodeRPCError(NetworkError):
    pass

class SessionNetwork:
    def __init__(self, proxy: Optional[str] = None):
        """
        proxy: proxy URL (e.g. 'socks5h://user:pass@host:port' or 'http://host:port')
        """
        self.proxy = proxy
        self.session = requests.Session()
        if proxy:
            # Normalize socks5 to socks5h for remote DNS resolution
            if proxy.startswith("socks5://"):
                proxy = "socks5h://" + proxy[len("socks5://"):]
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
            
    def request(self, method: str, url: str, json_data: dict, headers: Optional[dict] = None, timeout: int = 10) -> dict:
        default_headers = {
            "User-Agent": "WhatsApp",
            "Accept-Language": "en-us",
            "Content-Type": "application/json"
        }
        if headers:
            default_headers.update(headers)
            
        try:
            # We disable SSL certificate verification for storage node RPCs because
            # storage nodes use self-signed certificates in the Session network.
            response = self.session.post(
                url,
                json=json_data,
                headers=default_headers,
                timeout=timeout,
                verify=False
            )
            
            if response.status_code == 421:
                raise SnodeRPCError("421 handled. Retry this request with a new snode.")
                
            if not response.ok:
                raise SnodeRPCError(f"HTTP Error {response.status_code}: {response.text}")
                
            return response.json()
        except requests.RequestException as e:
            raise SnodeFetchError(f"Network request failed: {e}")

    def get_snodes_from_seeds(self) -> List[Dict[str, Any]]:
        # Randomize seeds list
        seeds_pool = list(SEEDS)
        random.shuffle(seeds_pool)
        
        for seed in seeds_pool:
            url = f"http://{seed['url']}/json_rpc"
            body = {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "get_n_service_nodes",
                "params": {
                    "fields": {
                        "public_ip": True,
                        "storage_port": True,
                        "pubkey_x25519": True,
                        "pubkey_ed25519": True
                    }
                }
            }
            try:
                res = self.request("POST", url, body, timeout=8)
                if "result" in res and "service_node_states" in res["result"]:
                    snodes = res["result"]["service_node_states"]
                    # Filter out nodes with invalid IP
                    filtered_snodes = [
                        s for s in snodes 
                        if s.get("public_ip") and s["public_ip"] != "0.0.0.0"
                    ]
                    if filtered_snodes:
                        return filtered_snodes
            except Exception as e:
                # Fallback to next seed
                continue
                
        raise SnodeFetchError("Failed to fetch service nodes from all seed nodes.")

    def snode_batch_request(
        self, 
        snode: Dict[str, Any], 
        requests_list: List[Dict[str, Any]], 
        timeout: int = 10,
        method: str = "batch"
    ) -> List[Dict[str, Any]]:
        """
        snode: dict containing public_ip, storage_port
        requests_list: list of subrequests, e.g. [{"method": "get_swarm", "params": {...}}]
        """
        url = f"https://{snode['public_ip']}:{snode['storage_port']}/storage_rpc/v1"
        body = {
            "jsonrpc": "2.0",
            "method": method,
            "params": {
                "requests": requests_list
            }
        }
        res = self.request("POST", url, body, timeout=timeout)
        if "results" not in res:
            raise SnodeRPCError(f"Invalid snode RPC response (no 'results'): {res}")
            
        return res["results"]

    def upload_attachment(self, data: bytes, timeout: int = 30) -> dict:
        url = "http://filev2.getsession.org/file"
        try:
            response = self.session.post(
                url,
                data=data,
                headers={"User-Agent": "WhatsApp"},
                timeout=timeout
            )
            if not response.ok:
                raise NetworkError(f"Upload failed with status code {response.status_code}")
            res_json = response.json()
            file_id = res_json["id"]
            return {
                "id": int(file_id),
                "url": f"http://filev2.getsession.org/file/{file_id}"
            }
        except Exception as e:
            raise NetworkError(f"Failed to upload attachment: {e}")

    def download_attachment(self, file_id: Union[int, str], timeout: int = 30) -> bytes:
        url = f"http://filev2.getsession.org/file/{file_id}"
        try:
            response = self.session.get(
                url,
                headers={"User-Agent": "WhatsApp"},
                timeout=timeout
            )
            if not response.ok:
                raise NetworkError(f"Download failed with status code {response.status_code}")
            return response.content
        except Exception as e:
            raise NetworkError(f"Failed to download attachment: {e}")

    def sogs_request(
        self,
        host: str,
        endpoint: str,
        method: str,
        body: Optional[Union[str, bytes]] = None,
        headers: Optional[dict] = None,
        timeout: int = 15
    ) -> dict:
        url = host + endpoint
        default_headers = {"User-Agent": "WhatsApp"}
        if headers:
            default_headers.update(headers)
        try:
            res = self.session.request(
                method=method,
                url=url,
                data=body,
                headers=default_headers,
                timeout=timeout
            )
            return res.json()
        except Exception as e:
            raise NetworkError(f"Failed SOGS request: {e}")
