<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Password;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class PasswordResetTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        Role::create(['name' => 'super-admin', 'guard_name' => 'web']);

        $tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test.example.com', 'status' => 'active']);

        $this->user = User::create([
            'tenant_id' => $tenant->id,
            'name' => 'Test User',
            'email' => 'reset@example.com',
            'phone' => '0700000000',
            'password' => 'OldPassword123!',
            'status' => 'active',
        ]);
        $this->user->assignRole('super-admin');
    }

    public function test_forgot_password_returns_success_for_existing_email(): void
    {
        $response = $this->postJson('/api/v1/password/forgot', ['email' => 'reset@example.com']);

        $response->assertStatus(200);
    }

    public function test_forgot_password_does_not_leak_whether_email_exists(): void
    {
        $response = $this->postJson('/api/v1/password/forgot', ['email' => 'nobody@example.com']);

        // Should not error or reveal non-existence — same generic response either way.
        $response->assertStatus(200);
    }

    public function test_reset_with_valid_token_changes_password(): void
    {
        $token = Password::createToken($this->user);

        $response = $this->postJson('/api/v1/password/reset', [
            'email' => 'reset@example.com',
            'token' => $token,
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $response->assertStatus(200);

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => 'reset@example.com',
            'password' => 'NewPassword456!',
        ]);
        $loginResponse->assertStatus(200);
    }

    public function test_reset_revokes_all_existing_tokens(): void
    {
        $oldToken = $this->user->createToken('old-session')->plainTextToken;
        $this->assertSame(1, $this->user->fresh()->tokens()->count());

        $resetToken = Password::createToken($this->user);

        $this->postJson('/api/v1/password/reset', [
            'email' => 'reset@example.com',
            'token' => $resetToken,
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $this->assertSame(0, $this->user->fresh()->tokens()->count());
    }

    public function test_reset_with_invalid_token_fails(): void
    {
        $response = $this->postJson('/api/v1/password/reset', [
            'email' => 'reset@example.com',
            'token' => 'completely-invalid-token',
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $response->assertStatus(422);
    }

    public function test_reset_with_mismatched_confirmation_fails(): void
    {
        $token = Password::createToken($this->user);

        $response = $this->postJson('/api/v1/password/reset', [
            'email' => 'reset@example.com',
            'token' => $token,
            'password' => 'NewPassword456!',
            'password_confirmation' => 'DifferentPassword!',
        ]);

        $response->assertStatus(422);
    }

    public function test_old_password_no_longer_works_after_reset(): void
    {
        $token = Password::createToken($this->user);

        $this->postJson('/api/v1/password/reset', [
            'email' => 'reset@example.com',
            'token' => $token,
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $response = $this->postJson('/api/v1/login', [
            'email' => 'reset@example.com',
            'password' => 'OldPassword123!',
        ]);

        $response->assertStatus(401);
    }
}
