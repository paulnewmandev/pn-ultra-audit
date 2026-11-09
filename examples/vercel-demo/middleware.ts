import { NextResponse } from 'next/server'
export function middleware(req) { const session = req.cookies.get('session'); if (!session) return NextResponse.redirect('/login'); return NextResponse.next() }
export const config = { matcher: ['/((?!api|_next/static|favicon.ico).*)'] }
