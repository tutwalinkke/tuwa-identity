<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class TokenExpirationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Role::create(['name' => 'super-admin', 'guard_name' => 'web']);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    protected function makeUser(): User
    {
        $tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test.example.com', 'status' => 'active']);

        $user = User::create([
            'tenant_id' => $tenant->id,
            'name' => 'Test User',
            'email' => 'expiry@example.com',
            'phone' => '0700000000',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $user->assignRole('super-admin');

        return $user;
    }

    public function test_login_response_includes_a_real_expiry_timestamp(): void
    {
        $this->makeUser();

        $response = $this->postJson('/api/v1/login', [
            'email' => 'expiry@example.com',
            'password' => 'Password123!',
        ]);

        $response->assertStatus(200);
        $this->assertNotNull($response->json('expires_at'));
    }

    public function test_token_works_before_expiration(): void
    {
        $this->makeUser();

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => 'expiry@example.com',
            'password' => 'Password123!',
        ]);
        $token = $loginResponse->json('token');

        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(200);
    }

    public function test_token_is_rejected_after_expiration(): void
    {
        $this->makeUser();

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => 'expiry@example.com',
            'password' => 'Password123!',
        ]);
        $token = $loginResponse->json('token');

        // Travel forward past the configured expiration window (30 min
        // default, but read from config so this test stays correct even
        // if the expiration duration is changed later).
        $expirationMinutes = config('sanctum.expiration');
        Carbon::setTestNow(now()->addMinutes($expirationMinutes + 1));

        $this->app['auth']->forgetGuards();

        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(401);
    }

    public function test_token_still_valid_one_minute_before_expiration(): void
    {
        $this->makeUser();

        $loginResponse = $this->postJson('/api/v1/login', [
            'email' => 'expiry@example.com',
            'password' => 'Password123!',
        ]);
        $token = $loginResponse->json('token');

        $expirationMinutes = config('sanctum.expiration');
        Carbon::setTestNow(now()->addMinutes($expirationMinutes - 1));

        $this->app['auth']->forgetGuards();

        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(200);
    }
}
