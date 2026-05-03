import { NextRequest, NextResponse } from 'next/server';
import { ADMIN_COOKIE, createJWT } from '@/lib/utils/admin-auth';

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();

    const adminSecret = process.env.ADMIN_SECRET;

    if (!adminSecret) {
      return NextResponse.json(
        { error: 'ADMIN_SECRET is not configured' },
        { status: 500 }
      );
    }

    if (!username || !password) {
      return NextResponse.json(
        { error: 'Username and password required' },
        { status: 400 }
      );
    }

    const isValid =
      username === 'admin' &&
      password === adminSecret;

    if (!isValid) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    const token = await createJWT({
      userId: 'admin',
      username: 'admin',
    });

    const response = NextResponse.json({
      success: true,
      user: {
        id: 'admin',
        username: 'admin',
        role: 'admin',
      },
    });

    response.cookies.set(ADMIN_COOKIE, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60,
      path: '/',
    });

    return response;
  } catch (error) {
    console.error('Admin auth error:', error);

    return NextResponse.json(
      { error: 'Authentication failed' },
      { status: 500 }
    );
  }
}

export async function DELETE() {
  const response = NextResponse.json({ success: true });
  response.cookies.delete(ADMIN_COOKIE);
  return response;
}
