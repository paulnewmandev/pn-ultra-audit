import os
BASE = os.path.realpath('/data')
def read(request):
    name = request.args.get('f')
    p = os.path.realpath(os.path.join(BASE, name))
    if not p.startswith(BASE + os.sep): raise PermissionError
    return open(p).read()
