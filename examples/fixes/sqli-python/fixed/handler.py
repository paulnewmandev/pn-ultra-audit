def get(request, cur):
    name = request.args.get('name')
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    return cur.fetchall()
