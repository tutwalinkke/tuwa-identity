<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\PasswordResetController;
use App\Http\Controllers\Auth\EmailVerificationController;
use App\Http\Controllers\Auth\TwoFactorController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\TenantController;
use App\Http\Controllers\ActivityController;

Route::prefix('v1')->group(function () {

    Route::middleware('throttle:login')->post('/login', [LoginController::class, 'login']);

    Route::middleware(['auth:sanctum', 'require.pending2fa', 'throttle:login'])
        ->post('/login/verify-two-factor', [LoginController::class, 'verifyTwoFactor']);

    Route::middleware('throttle:password-forgot')->post('/password/forgot', [PasswordResetController::class, 'forgot']);
    Route::middleware('throttle:password-reset')->post('/password/reset', [PasswordResetController::class, 'reset']);

    Route::get('/email/verify/{id}/{hash}', [EmailVerificationController::class, 'verify'])
        ->middleware('signed')
        ->name('verification.verify');

    Route::middleware(['auth:sanctum', 'tenant.active', 'reject.pending2fa'])->group(function () {
        Route::post('/logout', [LoginController::class, 'logout']);
        Route::get('/me', [LoginController::class, 'me']);
        Route::post('/email/verify/resend', [EmailVerificationController::class, 'resend']);

        Route::get('/users', [UserController::class, 'index']);
        Route::post('/users', [UserController::class, 'store']);
        Route::patch('/users/{id}/role', [UserController::class, 'updateRole']);
        Route::patch('/users/{id}/status', [UserController::class, 'updateStatus']);

        Route::get('/tenants/{id}', [TenantController::class, 'show']);

        Route::get('/activity', [ActivityController::class, 'index']);

        Route::get('/two-factor/status', [TwoFactorController::class, 'status']);
        Route::post('/two-factor/setup', [TwoFactorController::class, 'setup']);
        Route::post('/two-factor/confirm', [TwoFactorController::class, 'confirm']);
        Route::post('/two-factor/disable', [TwoFactorController::class, 'disable']);
    });

});
