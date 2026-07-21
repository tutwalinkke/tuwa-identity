<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * The inverse of RejectPendingTwoFactorToken — only allows requests
 * authenticated with a genuine pending-2FA token to reach the
 * verification endpoint. A normal, fully-authenticated session token
 * cannot be used here either, preventing this endpoint from becoming
 * an unintended alternate path for anything else.
 */
class RequirePendingTwoFactorToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->user()?->currentAccessToken();

        if (! $token || ! method_exists($token, 'can') || ! $token->can('2fa-pending')) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        return $next($request);
    }
}
