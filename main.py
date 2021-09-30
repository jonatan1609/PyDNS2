from PyDNS2.send_request import send_request, Question, Header

DOMAIN = "www.google.com"


for name, ip in {
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1"
}.items():
    response = send_request(
        ip,
        Header(1),
        [Question(DOMAIN)]
    )
    print(f"IP for {DOMAIN!r} in {name}'s DNSs is {response.resources[0].ip} (cache for {response.ttl} seconds)")