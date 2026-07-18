<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureActiveTenant
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        // super-admin bypasses tenant restrictions entirely —
        // needed for platform-level operators managing all tenants.
        if ($user->hasRole('super-admin')) {
            return $next($request);
        }

        $tenant = $user->tenant;

        if (! $tenant) {
            return response()->json(['message' => 'No tenant associated with this account.'], 403);
        }

        if ($tenant->status !== 'active') {
            return response()->json(['message' => 'This tenant account is not active.'], 403);
        }

        // Make tenant available to controllers without re-querying.
        $request->attributes->set('tenant', $tenant);

        return $next($request);
    }
}
