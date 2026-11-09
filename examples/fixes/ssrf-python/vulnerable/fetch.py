import requests
def fetch(request):
    return requests.get(request.args.get('url'), timeout=5).text
