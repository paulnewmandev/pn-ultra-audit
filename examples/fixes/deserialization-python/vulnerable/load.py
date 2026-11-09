import pickle
def load(request):
    return pickle.loads(request.data)
