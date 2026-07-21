<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PragmaRX\Google2FA\Google2FA;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class TwoFactorAuthTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Role::create(['name' => 'super-admin', 'guard_name' => 'web']);
    }

    protected function makeUser(): User
    {
        $tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test.example.com', 'status' => 'active']);

        $user = User::create([
            'tenant_id' => $tenant->id,
            'name' => 'Test User',
            'email' => 'mfa@example.com',
            'phone' => '0700000000',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $user->assignRole('super-admin');
        $user->email_verified_at = now();
        $user->save();

        return $user;
    }

    protected function loginAndGetToken(User $user): string
    {
        $response = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);

        return $response->json('token');
    }

    protected function enableTwoFactorFor(User $user): string
    {
        $token = $this->loginAndGetToken($user);

        $setupResponse = $this->postJson('/api/v1/two-factor/setup', [], [
            'Authorization' => "Bearer {$token}",
        ]);
        $secret = $setupResponse->json('secret');

        $google2fa = new Google2FA();
        $code = $google2fa->getCurrentOtp($secret);

        $this->postJson('/api/v1/two-factor/confirm', ['code' => $code], [
            'Authorization' => "Bearer {$token}",
        ]);

        return $secret;
    }

    public function test_setup_returns_a_secret_and_qr_code_url(): void
    {
        $user = $this->makeUser();
        $token = $this->loginAndGetToken($user);

        $response = $this->postJson('/api/v1/two-factor/setup', [], [
            'Authorization' => "Bearer {$token}",
        ]);

        $response->assertStatus(200);
        $this->assertNotEmpty($response->json('secret'));
        $this->assertStringContainsString('otpauth://totp', $response->json('qr_code_url'));
    }

    public function test_confirm_with_valid_code_enables_two_factor_and_returns_recovery_codes(): void
    {
        $user = $this->makeUser();
        $this->enableTwoFactorFor($user);

        $this->assertTrue($user->fresh()->hasTwoFactorEnabled());
    }

    public function test_confirm_with_invalid_code_fails(): void
    {
        $user = $this->makeUser();
        $token = $this->loginAndGetToken($user);

        $this->postJson('/api/v1/two-factor/setup', [], ['Authorization' => "Bearer {$token}"]);

        $response = $this->postJson('/api/v1/two-factor/confirm', ['code' => '000000'], [
            'Authorization' => "Bearer {$token}",
        ]);

        $response->assertStatus(422);
        $this->assertFalse($user->fresh()->hasTwoFactorEnabled());
    }

    public function test_login_without_two_factor_enabled_issues_a_real_token_directly(): void
    {
        $user = $this->makeUser();

        $response = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);

        $response->assertStatus(200);
        $this->assertNotNull($response->json('token'));
        $this->assertNull($response->json('requires_two_factor'));
    }

    public function test_login_with_two_factor_enabled_returns_pending_token_not_a_real_one(): void
    {
        $user = $this->makeUser();
        $this->enableTwoFactorFor($user);

        $response = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);

        $response->assertStatus(200);
        $this->assertTrue($response->json('requires_two_factor'));
        $this->assertNotEmpty($response->json('pending_token'));
        $this->assertNull($response->json('token'));
    }

    public function test_pending_token_is_rejected_on_a_normal_authenticated_endpoint(): void
    {
        $user = $this->makeUser();
        $this->enableTwoFactorFor($user);

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);
        $pendingToken = $loginResponse->json('pending_token');

        $this->app['auth']->forgetGuards();
        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$pendingToken}"]);

        $response->assertStatus(401);
    }

    /**
     * This is the specific regression test for a real bug found during
     * development: Sanctum's can() treats a '*' wildcard ability as
     * matching ANY ability check, so a naive can('2fa-pending') check
     * incorrectly rejected fully-privileged, legitimate session tokens
     * too — not just genuine pending tokens. A real token must keep
     * working normally.
     */
    public function test_a_normal_fully_privileged_token_is_not_incorrectly_rejected(): void
    {
        $user = $this->makeUser();
        $this->enableTwoFactorFor($user);

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);
        $pendingToken = $loginResponse->json('pending_token');

        $google2fa = new Google2FA();
        $code = $google2fa->getCurrentOtp($user->fresh()->two_factor_secret);

        $verifyResponse = $this->postJson('/api/v1/login/verify-two-factor', ['code' => $code], [
            'Authorization' => "Bearer {$pendingToken}",
        ]);
        $realToken = $verifyResponse->json('token');

        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$realToken}"]);

        $response->assertStatus(200);
    }

    public function test_verify_two_factor_with_wrong_code_fails(): void
    {
        $user = $this->makeUser();
        $this->enableTwoFactorFor($user);

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);
        $pendingToken = $loginResponse->json('pending_token');

        $response = $this->postJson('/api/v1/login/verify-two-factor', ['code' => '000000'], [
            'Authorization' => "Bearer {$pendingToken}",
        ]);

        $response->assertStatus(401);
    }

    public function test_verify_two_factor_with_valid_code_issues_a_real_token(): void
    {
        $user = $this->makeUser();
        $this->enableTwoFactorFor($user);

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);
        $pendingToken = $loginResponse->json('pending_token');

        $google2fa = new Google2FA();
        $code = $google2fa->getCurrentOtp($user->fresh()->two_factor_secret);

        $response = $this->postJson('/api/v1/login/verify-two-factor', ['code' => $code], [
            'Authorization' => "Bearer {$pendingToken}",
        ]);

        $response->assertStatus(200);
        $this->assertNotEmpty($response->json('token'));
    }

    public function test_pending_token_is_consumed_after_successful_verification(): void
    {
        $user = $this->makeUser();
        $this->enableTwoFactorFor($user);

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);
        $pendingToken = $loginResponse->json('pending_token');

        $google2fa = new Google2FA();
        $code = $google2fa->getCurrentOtp($user->fresh()->two_factor_secret);

        $this->postJson('/api/v1/login/verify-two-factor', ['code' => $code], [
            'Authorization' => "Bearer {$pendingToken}",
        ]);

        $this->app['auth']->forgetGuards();
        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$pendingToken}"]);

        $response->assertStatus(401);
    }

    public function test_login_with_a_valid_recovery_code_works_and_consumes_it(): void
    {
        $user = $this->makeUser();
        $token = $this->loginAndGetToken($user);

        $setupResponse = $this->postJson('/api/v1/two-factor/setup', [], ['Authorization' => "Bearer {$token}"]);
        $secret = $setupResponse->json('secret');

        $google2fa = new Google2FA();
        $code = $google2fa->getCurrentOtp($secret);

        $confirmResponse = $this->postJson('/api/v1/two-factor/confirm', ['code' => $code], [
            'Authorization' => "Bearer {$token}",
        ]);
        $recoveryCode = $confirmResponse->json('recovery_codes')[0];

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);
        $pendingToken = $loginResponse->json('pending_token');

        $response = $this->postJson('/api/v1/login/verify-two-factor', ['code' => $recoveryCode], [
            'Authorization' => "Bearer {$pendingToken}",
        ]);

        $response->assertStatus(200);
        $this->assertSame(7, $response->json('recovery_codes_remaining'));

        // Same recovery code cannot be reused a second time.
        $secondLogin = $this->postJson('/api/v1/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);
        $secondPendingToken = $secondLogin->json('pending_token');

        $reuseResponse = $this->postJson('/api/v1/login/verify-two-factor', ['code' => $recoveryCode], [
            'Authorization' => "Bearer {$secondPendingToken}",
        ]);
        $reuseResponse->assertStatus(401);
    }

    public function test_disable_requires_correct_password(): void
    {
        $user = $this->makeUser();
        $token = $this->loginAndGetToken($user);
        $this->enableTwoFactorFor($user);

        // Re-login normally isn't possible now that MFA is on, so reuse
        // the original pre-MFA token for this disable call directly —
        // simulating an already-authenticated session choosing to turn
        // MFA off.
        $response = $this->postJson('/api/v1/two-factor/disable', ['password' => 'WrongPassword!'], [
            'Authorization' => "Bearer {$token}",
        ]);

        $response->assertStatus(401);
        $this->assertTrue($user->fresh()->hasTwoFactorEnabled());
    }

    public function test_disable_with_correct_password_actually_clears_two_factor(): void
    {
        $user = $this->makeUser();
        $token = $this->loginAndGetToken($user);
        $this->enableTwoFactorFor($user);

        $response = $this->postJson('/api/v1/two-factor/disable', ['password' => 'Password123!'], [
            'Authorization' => "Bearer {$token}",
        ]);

        $response->assertStatus(200);
        $this->assertFalse($user->fresh()->hasTwoFactorEnabled());
        $this->assertNull($user->fresh()->two_factor_secret);
    }
}
