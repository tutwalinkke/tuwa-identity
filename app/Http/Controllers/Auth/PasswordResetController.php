<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Str;

class PasswordResetController extends Controller
{
    public function forgot(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
        ]);

        $status = Password::sendResetLink(
            $request->only('email')
        );

        if ($status === Password::RESET_LINK_SENT) {
            return response()->json([
                'message' => 'Password reset link sent.'
            ]);
        }

        // Deliberately vague response even on failure, to avoid leaking
        // which emails exist in the system (user enumeration protection).
        return response()->json([
            'message' => 'If that email exists, a reset link has been sent.'
        ]);
    }

    public function reset(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'token' => 'required',
            'password' => 'required|min:8|confirmed',
        ]);

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function (User $user, string $password) {
                $user->forceFill([
                    'password' => $password,
                ])->save();

                // Revoke all existing tokens — force re-login everywhere
                // after a password reset, since old tokens were issued
                // under the compromised/forgotten credential.
                $user->tokens()->delete();

                activity()
                    ->causedBy($user)
                    ->log('Password reset completed');

                event(new PasswordReset($user));
            }
        );

        if ($status === Password::PASSWORD_RESET) {
            return response()->json([
                'message' => 'Password has been reset successfully.'
            ]);
        }

        return response()->json([
            'message' => __($status)
        ], 422);
    }
}
