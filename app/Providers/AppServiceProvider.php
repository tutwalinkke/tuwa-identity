<?php

namespace App\Providers;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {
        ResetPassword::createUrlUsing(function ($notifiable, string $token) {
            $frontendUrl = config('app.frontend_url');

            return $frontendUrl
                . '/reset-password?token=' . $token
                . '&email=' . urlencode($notifiable->getEmailForPasswordReset());
        });

        VerifyEmail::createUrlUsing(function ($notifiable) {
            $backendSignedUrl = URL::temporarySignedRoute(
                'verification.verify',
                now()->addMinutes(60),
                [
                    'id' => $notifiable->getKey(),
                    'hash' => sha1($notifiable->getEmailForVerification()),
                ]
            );

            $frontendUrl = config('app.frontend_url');

            return $frontendUrl . '/verify-email?verify_url=' . urlencode($backendSignedUrl);
        });

        // Named rate limiters, each keyed explicitly by route name + IP so
        // they never share a bucket with each other. Laravel's shorthand
        // throttle:max,decay syntax keys only by domain+IP, which would
        // silently let hitting one endpoint's limit consume another's —
        // these named limiters avoid that entirely.
        RateLimiter::for('login', function ($request) {
            return Limit::perMinute(5)->by('login:' . $request->ip());
        });

        RateLimiter::for('password-forgot', function ($request) {
            return Limit::perMinute(3)->by('password-forgot:' . $request->ip());
        });

        RateLimiter::for('password-reset', function ($request) {
            return Limit::perMinute(5)->by('password-reset:' . $request->ip());
        });
    }
}
