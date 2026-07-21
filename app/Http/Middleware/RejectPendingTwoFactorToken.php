<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Blocks any request authenticated with a pending-2FA token from
 * reaching normal, fully-authenticated endpoints. Deliberately checks
 * the token's abilities directly via Sanctum's own can() method rather
 * than depending on the built-in 'abilities' middleware, since this
 * app's auth:sanctum alias is configured non-standardly (aliased to
 * EnsureFrontendRequestsAreStateful rather than the usual parameterized
 * Authenticate::class pattern) and the built-in middleware did not
 * reliably enforce the restriction here — confirmed by live testing,
 * not assumed.
 */
class RejectPendingTwoFactorToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->user()?->currentAccessToken();

        // Check the token's actual ability list directly rather than
        // via can('2fa-pending') — Sanctum's can() treats a '*' wildcard
        // ability (which every normal, fully-privileged session token
        // has) as matching ANY ability check, including this one. That
        // meant a real, fully-authenticated token was being incorrectly
        // rejected here too. A pending-2FA token's ability list is
        // exactly ['2fa-pending'], nothing else — check for that
        // specifically, not through the wildcard-aware can() helper.
        $abilities = $token?->abilities ?? [];

        if (in_array('2fa-pending', $abilities, true) && ! in_array('*', $abilities, true)) {
            return response()->json(['message' => 'Two-factor verification required.'], 401);
        }

        return $next($request);
    }
}
