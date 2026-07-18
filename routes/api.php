<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\PasswordResetController;
use App\Http\Controllers\Auth\EmailVerificationController;

Route::prefix('v1')->group(function () {

    Route::post('/login', [LoginController::class, 'login']);

    Route::post('/password/forgot', [PasswordResetController::class, 'forgot']);
    Route::post('/password/reset', [PasswordResetController::class, 'reset']);

    Route::get('/email/verify/{id}/{hash}', [EmailVerificationController::class, 'verify'])
        ->middleware('signed')
        ->name('verification.verify');

    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/logout', [LoginController::class, 'logout']);
        Route::get('/me', [LoginController::class, 'me']);
        Route::post('/email/verify/resend', [EmailVerificationController::class, 'resend']);
    });

});
