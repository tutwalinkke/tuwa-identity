<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

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

        $user->update([
            'last_login_at' => now()
        ]);

        $expirationMinutes = config('sanctum.expiration');
        $expiresAt = $expirationMinutes ? now()->addMinutes($expirationMinutes) : null;

        $token = $user->createToken('identity-token', ['*'], $expiresAt)->plainTextToken;

        activity()
            ->causedBy($user)
            ->log('User logged in');

        return response()->json([
            'user' => $user->fresh(),
            'roles' => $user->getRoleNames(),
            'token' => $token,
            'expires_at' => $expiresAt,
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
