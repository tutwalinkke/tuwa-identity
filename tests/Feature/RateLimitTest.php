<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class RateLimitTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        // Laravel's throttle middleware keys rate-limit buckets internally
        // by route signature + IP, not by a predictable string — and the
        // 'array' cache store used in tests persists for the whole test
        // process, not per-method. Flushing the entire store here is the
        // reliable way to guarantee each test starts with a clean slate,
        // rather than guessing at internal key names.
        Cache::flush();

        Role::create(['name' => 'super-admin', 'guard_name' => 'web']);

        $tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test.example.com', 'status' => 'active']);

        User::create([
            'tenant_id' => $tenant->id,
            'name' => 'Test User',
            'email' => 'ratelimit@example.com',
            'phone' => '0700000000',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
    }

    public function test_login_is_rate_limited_after_five_attempts(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $response = $this->postJson('/api/v1/login', [
                'email' => 'ratelimit@example.com',
                'password' => 'wrong-password',
            ]);
            $response->assertStatus(401);
        }

        $response = $this->postJson('/api/v1/login', [
            'email' => 'ratelimit@example.com',
            'password' => 'wrong-password',
        ]);

        $response->assertStatus(429);
    }

    public function test_password_forgot_is_rate_limited_after_three_attempts(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $response = $this->postJson('/api/v1/password/forgot', [
                'email' => 'ratelimit@example.com',
            ]);
            $response->assertStatus(200);
        }

        $response = $this->postJson('/api/v1/password/forgot', [
            'email' => 'ratelimit@example.com',
        ]);

        $response->assertStatus(429);
    }

    public function test_hitting_logins_limit_does_not_consume_password_forgots_limit(): void
    {
        // Regression guard: named rate limiters with distinct keys must
        // not share a bucket. Laravel's shorthand throttle:max,decay syntax
        // keys only by domain+IP, which would let exhausting login's limit
        // silently consume password/forgot's separate limit too — this
        // proves the fix (named limiters with explicit distinct keys) works.
        for ($i = 0; $i < 5; $i++) {
            $this->postJson('/api/v1/login', [
                'email' => 'ratelimit@example.com',
                'password' => 'wrong-password',
            ]);
        }

        $blockedLogin = $this->postJson('/api/v1/login', [
            'email' => 'ratelimit@example.com',
            'password' => 'wrong-password',
        ]);
        $blockedLogin->assertStatus(429);

        $forgotStillWorks = $this->postJson('/api/v1/password/forgot', [
            'email' => 'ratelimit@example.com',
        ]);
        $forgotStillWorks->assertStatus(200);
    }
}
