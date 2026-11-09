export async function GET() { await syncEverything(); return Response.json({ ok: true }) }
