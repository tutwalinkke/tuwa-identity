<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    protected Tenant $tenant;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tenant = Tenant::create([
            'name' => 'Test Tenant',
            'domain' => 'test.example.com',
            'status' => 'active',
        ]);

        Role::create(['name' => 'super-admin', 'guard_name' => 'web']);
    }

    protected function makeUser(string $password = 'ValidPassword123!'): User
    {
        $user = User::create([
            'tenant_id' => $this->tenant->id,
            'name' => 'Test User',
            'email' => 'test@example.com',
            'phone' => '0700000000',
            'password' => $password,
            'status' => 'active',
        ]);

        $user->assignRole('super-admin');

        return $user;
    }

    public function test_login_with_correct_credentials_succeeds(): void
    {
        $this->makeUser('CorrectPassword123!');

        $response = $this->postJson('/api/v1/login', [
            'email' => 'test@example.com',
            'password' => 'CorrectPassword123!',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure(['user', 'roles', 'token']);
    }

    public function test_login_with_wrong_password_fails(): void
    {
        $this->makeUser('CorrectPassword123!');

        $response = $this->postJson('/api/v1/login', [
            'email' => 'test@example.com',
            'password' => 'WrongPassword!',
        ]);

        $response->assertStatus(401)
            ->assertJson(['message' => 'Invalid credentials']);
    }

    public function test_login_with_nonexistent_email_fails(): void
    {
        $response = $this->postJson('/api/v1/login', [
            'email' => 'nobody@example.com',
            'password' => 'AnyPassword123!',
        ]);

        $response->assertStatus(401);
    }

    public function test_login_requires_email_and_password(): void
    {
        $response = $this->postJson('/api/v1/login', []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email', 'password']);
    }

    public function test_login_sets_last_login_at(): void
    {
        $user = $this->makeUser('CorrectPassword123!');
        $this->assertNull($user->last_login_at);

        $this->postJson('/api/v1/login', [
            'email' => 'test@example.com',
            'password' => 'CorrectPassword123!',
        ]);

        $this->assertNotNull($user->fresh()->last_login_at);
    }

    public function test_authenticated_user_can_access_me_endpoint(): void
    {
        $user = $this->makeUser();
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->getJson('/api/v1/me', [
            'Authorization' => "Bearer {$token}",
        ]);

        $response->assertStatus(200)
            ->assertJsonPath('user.email', 'test@example.com');
    }

    public function test_unauthenticated_request_to_me_is_rejected(): void
    {
        $response = $this->getJson('/api/v1/me');

        $response->assertStatus(401);
    }

    public function test_logout_revokes_the_current_token(): void
    {
        $user = $this->makeUser();
        $token = $user->createToken('test')->plainTextToken;

        $logoutResponse = $this->postJson('/api/v1/logout', [], [
            'Authorization' => "Bearer {$token}",
        ]);

        $logoutResponse->assertStatus(200);
        $this->assertSame(0, $user->fresh()->tokens()->count());

        // Force auth guards to re-resolve rather than reuse a cached
        // authenticated user from the previous request in this same
        // test process — real separate HTTP requests never share this
        // cache (each PHP-FPM request is a fresh process), but PHPUnit's
        // in-process test client can otherwise carry stale guard state
        // between sequential calls within a single test method.
        $this->app['auth']->forgetGuards();

        $meResponse = $this->getJson('/api/v1/me', [
            'Authorization' => "Bearer {$token}",
        ]);
        $meResponse->assertStatus(401);
    }

    public function test_invalid_token_is_rejected(): void
    {
        $response = $this->getJson('/api/v1/me', [
            'Authorization' => 'Bearer this-is-not-a-real-token',
        ]);

        $response->assertStatus(401);
    }
}
