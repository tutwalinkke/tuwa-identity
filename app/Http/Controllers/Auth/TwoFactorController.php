<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use PragmaRX\Google2FA\Google2FA;

class TwoFactorController extends Controller
{
    /**
     * Begin setup: generate a new secret, return it along with a QR
     * code image (as a data URI) for the user to scan with their
     * authenticator app. Not yet saved as "confirmed" — the secret is
     * stored, but hasTwoFactorEnabled() stays false until the user
     * proves they can generate a real code from it.
     */
    public function setup(Request $request)
    {
        $user = $request->user();
        $google2fa = new Google2FA();

        $secret = $google2fa->generateSecretKey();

        $user->update([
            'two_factor_secret' => $secret,
            'two_factor_confirmed_at' => null,
        ]);

        $qrCodeUrl = $google2fa->getQRCodeUrl(
            config('app.name', 'Tuwa Identity'),
            $user->email,
            $secret
        );

        return response()->json([
            'secret' => $secret,
            'qr_code_url' => $qrCodeUrl,
        ]);
    }

    /**
     * Confirm setup: verify the code the user just generated from their
     * authenticator app actually matches the stored secret. Only on
     * success does two_factor_confirmed_at get set — this is the
     * moment MFA genuinely becomes active on the account, plus we
     * generate one-time recovery codes here, shown exactly once.
     */
    public function confirm(Request $request)
    {
        $request->validate(['code' => 'required|string']);

        $user = $request->user();

        if (! $user->two_factor_secret) {
            return response()->json(['message' => 'No pending two-factor setup found.'], 422);
        }

        $google2fa = new Google2FA();
        $valid = $google2fa->verifyKey($user->two_factor_secret, $request->code);

        if (! $valid) {
            return response()->json(['message' => 'Invalid code. Please try again.'], 422);
        }

        $recoveryCodes = collect(range(1, 8))
            ->map(fn () => strtoupper(bin2hex(random_bytes(4))))
            ->values()
            ->all();

        $user->update([
            'two_factor_confirmed_at' => now(),
            'two_factor_recovery_codes' => $recoveryCodes,
        ]);

        activity()->causedBy($user)->log('Two-factor authentication enabled');

        return response()->json([
            'message' => 'Two-factor authentication enabled.',
            'recovery_codes' => $recoveryCodes,
        ]);
    }

    public function disable(Request $request)
    {
        $request->validate(['password' => 'required|string']);

        $user = $request->user();

        if (! \Illuminate\Support\Facades\Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Incorrect password.'], 401);
        }

        $user->update([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ]);

        activity()->causedBy($user)->log('Two-factor authentication disabled');

        return response()->json(['message' => 'Two-factor authentication disabled.']);
    }

    public function status(Request $request)
    {
        return response()->json([
            'enabled' => $request->user()->hasTwoFactorEnabled(),
        ]);
    }
}
