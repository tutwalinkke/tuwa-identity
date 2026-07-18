<?php

namespace App\Providers;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
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
    }
}
