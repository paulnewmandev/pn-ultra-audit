import json
def load(request):
    return json.loads(request.data)
