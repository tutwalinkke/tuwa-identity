<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class ActivityLogTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Role::create(['name' => 'super-admin', 'guard_name' => 'web']);
        Role::create(['name' => 'tenant-admin', 'guard_name' => 'web']);
    }

    protected function makeUserWithRole(Tenant $tenant, string $role, string $email): User
    {
        $user = User::create([
            'tenant_id' => $tenant->id,
            'name' => 'Test User',
            'email' => $email,
            'phone' => '0700000000',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $user->assignRole($role);

        return $user;
    }

    public function test_login_produces_a_readable_activity_entry(): void
    {
        $tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test.example.com', 'status' => 'active']);
        $user = $this->makeUserWithRole($tenant, 'super-admin', 'admin@example.com');

        $this->postJson('/api/v1/login', [
            'email' => 'admin@example.com',
            'password' => 'Password123!',
        ]);

        $token = $user->createToken('test')->plainTextToken;
        $response = $this->getJson('/api/v1/activity', ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(200);
        $descriptions = collect($response->json('activities'))->pluck('description');
        $this->assertTrue($descriptions->contains('User logged in'));
    }

    public function test_noise_updated_entries_are_excluded(): void
    {
        $tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test2.example.com', 'status' => 'active']);
        $user = $this->makeUserWithRole($tenant, 'super-admin', 'admin2@example.com');

        $this->postJson('/api/v1/login', [
            'email' => 'admin2@example.com',
            'password' => 'Password123!',
        ]);

        $token = $user->createToken('test')->plainTextToken;
        $response = $this->getJson('/api/v1/activity', ['Authorization' => "Bearer {$token}"]);

        $descriptions = collect($response->json('activities'))->pluck('description');
        $this->assertFalse($descriptions->contains('updated'));
    }

    public function test_tenant_admin_only_sees_own_tenants_activity(): void
    {
        $tenantA = Tenant::create(['name' => 'Tenant A', 'domain' => 'a.example.com', 'status' => 'active']);
        $tenantB = Tenant::create(['name' => 'Tenant B', 'domain' => 'b.example.com', 'status' => 'active']);

        $adminA = $this->makeUserWithRole($tenantA, 'tenant-admin', 'admina@example.com');
        $adminB = $this->makeUserWithRole($tenantB, 'tenant-admin', 'adminb@example.com');

        $this->postJson('/api/v1/login', ['email' => 'admina@example.com', 'password' => 'Password123!']);
        $this->postJson('/api/v1/login', ['email' => 'adminb@example.com', 'password' => 'Password123!']);

        $tokenA = $adminA->createToken('test')->plainTextToken;
        $response = $this->getJson('/api/v1/activity', ['Authorization' => "Bearer {$tokenA}"]);

        $emails = collect($response->json('activities'))
            ->pluck('causer.email')
            ->filter();

        $this->assertTrue($emails->contains('admina@example.com'));
        $this->assertFalse($emails->contains('adminb@example.com'));
    }

    public function test_super_admin_sees_activity_across_all_tenants(): void
    {
        $tenantA = Tenant::create(['name' => 'Tenant A', 'domain' => 'a2.example.com', 'status' => 'active']);
        $tenantB = Tenant::create(['name' => 'Tenant B', 'domain' => 'b2.example.com', 'status' => 'active']);

        $superAdmin = $this->makeUserWithRole($tenantA, 'super-admin', 'super@example.com');
        $regularAdmin = $this->makeUserWithRole($tenantB, 'tenant-admin', 'regular@example.com');

        $this->postJson('/api/v1/login', ['email' => 'super@example.com', 'password' => 'Password123!']);
        $this->postJson('/api/v1/login', ['email' => 'regular@example.com', 'password' => 'Password123!']);

        $token = $superAdmin->createToken('test')->plainTextToken;
        $response = $this->getJson('/api/v1/activity', ['Authorization' => "Bearer {$token}"]);

        $emails = collect($response->json('activities'))
            ->pluck('causer.email')
            ->filter();

        $this->assertTrue($emails->contains('super@example.com'));
        $this->assertTrue($emails->contains('regular@example.com'));
    }

    public function test_unauthenticated_request_is_rejected(): void
    {
        $response = $this->getJson('/api/v1/activity');
        $response->assertStatus(401);
    }
}
