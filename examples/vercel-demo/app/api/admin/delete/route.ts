export async function POST(req: Request) { const { id } = await req.json(); await db.users.delete(id); return Response.json({ deleted: id }) }
