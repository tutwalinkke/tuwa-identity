<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\URL;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class EmailVerificationTest extends TestCase
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
            'email' => 'verify@example.com',
            'phone' => '0700000000',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $this->user->assignRole('super-admin');
    }

    protected function signedVerificationUrl(): string
    {
        return URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => $this->user->id,
                'hash' => sha1($this->user->getEmailForVerification()),
            ]
        );
    }

    public function test_valid_signed_url_verifies_the_email(): void
    {
        Event::fake();

        $this->assertNull($this->user->email_verified_at);

        $response = $this->getJson($this->signedVerificationUrl());

        $response->assertStatus(200);
        $this->assertNotNull($this->user->fresh()->email_verified_at);

        Event::assertDispatched(Verified::class);
    }

    public function test_verifying_an_already_verified_email_is_handled_gracefully(): void
    {
        $this->user->markEmailAsVerified();

        $response = $this->getJson($this->signedVerificationUrl());

        $response->assertStatus(200)
            ->assertJson(['message' => 'Email already verified.']);
    }

    public function test_url_with_invalid_hash_is_rejected(): void
    {
        $badUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => $this->user->id,
                'hash' => sha1('wrong-email@example.com'),
            ]
        );

        $response = $this->getJson($badUrl);

        $response->assertStatus(403);
        $this->assertNull($this->user->fresh()->email_verified_at);
    }

    public function test_expired_signature_is_rejected(): void
    {
        $expiredUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->subMinutes(5),
            [
                'id' => $this->user->id,
                'hash' => sha1($this->user->getEmailForVerification()),
            ]
        );

        $response = $this->getJson($expiredUrl);

        $response->assertStatus(403);
    }

    public function test_authenticated_user_can_request_resend(): void
    {
        $token = $this->user->createToken('test')->plainTextToken;

        $response = $this->postJson('/api/v1/email/verify/resend', [], [
            'Authorization' => "Bearer {$token}",
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Verification link sent.']);
    }

    public function test_resend_for_already_verified_user_says_so(): void
    {
        $this->user->markEmailAsVerified();
        $token = $this->user->createToken('test')->plainTextToken;

        $response = $this->postJson('/api/v1/email/verify/resend', [], [
            'Authorization' => "Bearer {$token}",
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Email already verified.']);
    }

    public function test_unauthenticated_resend_request_is_rejected(): void
    {
        $response = $this->postJson('/api/v1/email/verify/resend');

        $response->assertStatus(401);
    }
}
