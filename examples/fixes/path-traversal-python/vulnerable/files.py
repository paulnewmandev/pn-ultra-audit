def read(request):
    name = request.args.get('f')
    return open('/data/' + name).read()
