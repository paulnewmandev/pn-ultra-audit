import subprocess, ipaddress
def ping(request):
    host = str(ipaddress.ip_address(request.args.get('host')))
    subprocess.run(['ping', '-c', '1', host], check=True, timeout=5)
