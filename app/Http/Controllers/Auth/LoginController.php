<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use PragmaRX\Google2FA\Google2FA;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Invalid credentials'
            ], 401);
        }

        // Password is correct. If MFA is enabled, don't issue a real
        // session token yet — issue a short-lived, restricted-ability
        // token whose only valid use is completing the 2FA challenge.
        // A client holding this token cannot call any other endpoint;
        // Sanctum's ability system enforces that, not just our own logic.
        if ($user->hasTwoFactorEnabled()) {
            $pendingToken = $user->createToken(
                '2fa-pending',
                ['2fa-pending'],
                now()->addMinutes(5)
            )->plainTextToken;

            return response()->json([
                'requires_two_factor' => true,
                'pending_token' => $pendingToken,
            ]);
        }

        $user->update(['last_login_at' => now()]);

        $expirationMinutes = config('sanctum.expiration');
        $expiresAt = $expirationMinutes ? now()->addMinutes($expirationMinutes) : null;

        $token = $user->createToken('identity-token', ['*'], $expiresAt)->plainTextToken;

        activity()->causedBy($user)->log('User logged in');

        return response()->json([
            'user' => $user->fresh(),
            'roles' => $user->getRoleNames(),
            'token' => $token,
            'expires_at' => $expiresAt,
        ]);
    }

    /**
     * Second step of a two-factor login. Requires the short-lived
     * pending token from login() — the 'abilities:2fa-pending'
     * middleware on this route enforces that a normal session token
     * cannot be used here, and a pending token cannot be used anywhere
     * else. Accepts either a live TOTP code or a one-time recovery code.
     */
    public function verifyTwoFactor(Request $request)
    {
        $request->validate(['code' => 'required|string']);

        $user = $request->user();
        $code = $request->code;

        $google2fa = new Google2FA();
        $validTotp = $google2fa->verifyKey($user->two_factor_secret, $code);

        $validRecovery = false;
        $remainingRecoveryCodes = $user->two_factor_recovery_codes ?? [];

        if (! $validTotp && in_array(strtoupper($code), $remainingRecoveryCodes ?? [], true)) {
            $validRecovery = true;
            $remainingRecoveryCodes = array_values(array_diff($remainingRecoveryCodes, [strtoupper($code)]));
        }

        if (! $validTotp && ! $validRecovery) {
            return response()->json(['message' => 'Invalid code.'], 401);
        }

        // The pending token has done its job — remove it regardless of
        // which path succeeded, then issue a genuine session token.
        $request->user()->currentAccessToken()->delete();

        if ($validRecovery) {
            $user->update(['two_factor_recovery_codes' => $remainingRecoveryCodes]);
            activity()->causedBy($user)->log('Logged in using a two-factor recovery code');
        }

        $user->update(['last_login_at' => now()]);

        $expirationMinutes = config('sanctum.expiration');
        $expiresAt = $expirationMinutes ? now()->addMinutes($expirationMinutes) : null;

        $token = $user->createToken('identity-token', ['*'], $expiresAt)->plainTextToken;

        activity()->causedBy($user)->log('User logged in (two-factor verified)');

        return response()->json([
            'user' => $user->fresh(),
            'roles' => $user->getRoleNames(),
            'token' => $token,
            'expires_at' => $expiresAt,
            'recovery_codes_remaining' => count($remainingRecoveryCodes),
        ]);
    }

    public function logout(Request $request)
    {
        $user = $request->user();

        $request->user()->currentAccessToken()->delete();

        activity()
            ->causedBy($user)
            ->log('User logged out');

        return response()->json([
            'message' => 'Logged out successfully'
        ]);
    }

    public function me(Request $request)
    {
        $user = $request->user();

        return response()->json([
            'user' => $user,
            'roles' => $user->getRoleNames(),
            'permissions' => $user->getAllPermissions()->pluck('name'),
        ]);
    }
}
