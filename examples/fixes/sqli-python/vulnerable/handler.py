def get(request, cur):
    name = request.args.get('name')
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()
