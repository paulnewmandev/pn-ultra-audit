import requests
RATES_URL = 'https://api.example.com/rates'
def fetch(request):
    return requests.get(RATES_URL, timeout=5).text
