import { NextRequest, NextResponse } from 'next/server';
import { ADMIN_COOKIE, verifyJWTWithFallback } from '@/lib/utils/admin-auth';

const categories = [
  'analytics_view',
  'analytics_export',
  'user_management',
  'content_moderation',
  'system_settings',
  'user_data_access',
  'audit_logs',
  'bot_detection',
  'system_health',
];

export async function GET(request: NextRequest) {
  try {
    const token =
      request.cookies.get(ADMIN_COOKIE)?.value ||
      request.headers.get('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }

    const decoded = await verifyJWTWithFallback(token);

    if (!decoded || decoded.userId !== 'admin') {
      return NextResponse.json(
        { error: 'Invalid authentication token' },
        { status: 401 }
      );
    }

    const now = Date.now();

    return NextResponse.json({
      success: true,
      user: {
        id: 'admin',
        username: 'admin',
        role: 'super_admin',
        permissions: ['super_admin'],
        specificPermissions: categories,
        createdAt: now,
        lastLogin: now,
        permissionScope: {
          role: 'super_admin',
          permissions: ['super_admin'],
          categories,
          isAdmin: true,
          isSuperAdmin: true,
        },
      },
    });
  } catch (error) {
    console.error('Self-hosted admin me error:', error);

    return NextResponse.json(
      { error: 'Authentication failed' },
      { status: 500 }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}
