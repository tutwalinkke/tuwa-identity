<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class TenantIsolationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Role::create(['name' => 'super-admin', 'guard_name' => 'web']);
        Role::create(['name' => 'operator', 'guard_name' => 'web']);
    }

    protected function makeUserWithRole(Tenant $tenant, string $role, string $email): User
    {
        $user = User::create([
            'tenant_id' => $tenant->id,
            'name' => 'Test User',
            'email' => $email,
            'phone' => '0700000000',
            'password' => 'TestPassword123!',
            'status' => 'active',
        ]);

        $user->assignRole($role);

        return $user;
    }

    public function test_user_in_active_tenant_can_access_protected_routes(): void
    {
        $tenant = Tenant::create(['name' => 'Active Tenant', 'domain' => 'active.example.com', 'status' => 'active']);
        $user = $this->makeUserWithRole($tenant, 'operator', 'operator@active.example.com');
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(200);
    }

    public function test_user_in_suspended_tenant_is_blocked(): void
    {
        $tenant = Tenant::create(['name' => 'Suspended Tenant', 'domain' => 'suspended.example.com', 'status' => 'suspended']);
        $user = $this->makeUserWithRole($tenant, 'operator', 'operator@suspended.example.com');
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(403)
            ->assertJson(['message' => 'This tenant account is not active.']);
    }

    public function test_super_admin_bypasses_suspended_tenant_check(): void
    {
        $tenant = Tenant::create(['name' => 'Suspended Tenant', 'domain' => 'suspended2.example.com', 'status' => 'suspended']);
        $user = $this->makeUserWithRole($tenant, 'super-admin', 'admin@suspended2.example.com');
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(200);
    }

    public function test_tenant_admin_can_only_list_users_in_own_tenant(): void
    {
        Role::create(['name' => 'tenant-admin', 'guard_name' => 'web']);

        $tenantA = Tenant::create(['name' => 'Tenant A', 'domain' => 'a.example.com', 'status' => 'active']);
        $tenantB = Tenant::create(['name' => 'Tenant B', 'domain' => 'b.example.com', 'status' => 'active']);

        $adminA = $this->makeUserWithRole($tenantA, 'tenant-admin', 'admin@a.example.com');
        $this->makeUserWithRole($tenantA, 'operator', 'operator@a.example.com');
        $this->makeUserWithRole($tenantB, 'operator', 'operator@b.example.com');

        $token = $adminA->createToken('test')->plainTextToken;

        $response = $this->getJson('/api/v1/users', ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(200);
        $emails = collect($response->json('users'))->pluck('email');

        $this->assertTrue($emails->contains('admin@a.example.com'));
        $this->assertTrue($emails->contains('operator@a.example.com'));
        $this->assertFalse($emails->contains('operator@b.example.com'));
    }

    public function test_tenant_admin_cannot_access_user_in_different_tenant(): void
    {
        Role::create(['name' => 'tenant-admin', 'guard_name' => 'web']);

        $tenantA = Tenant::create(['name' => 'Tenant A', 'domain' => 'a2.example.com', 'status' => 'active']);
        $tenantB = Tenant::create(['name' => 'Tenant B', 'domain' => 'b2.example.com', 'status' => 'active']);

        $adminA = $this->makeUserWithRole($tenantA, 'tenant-admin', 'admin@a2.example.com');
        $userB = $this->makeUserWithRole($tenantB, 'operator', 'operator@b2.example.com');

        $token = $adminA->createToken('test')->plainTextToken;

        $response = $this->patchJson("/api/v1/users/{$userB->id}/status", ['status' => 'blocked'], [
            'Authorization' => "Bearer {$token}",
        ]);

        $response->assertStatus(403);
        $this->assertSame('active', $userB->fresh()->status);
    }

    public function test_tenant_admin_cannot_assign_super_admin_role(): void
    {
        Role::create(['name' => 'tenant-admin', 'guard_name' => 'web']);

        $tenant = Tenant::create(['name' => 'Tenant', 'domain' => 'c.example.com', 'status' => 'active']);
        $admin = $this->makeUserWithRole($tenant, 'tenant-admin', 'admin@c.example.com');
        $token = $admin->createToken('test')->plainTextToken;

        $response = $this->postJson('/api/v1/users', [
            'name' => 'Sneaky',
            'email' => 'sneaky@c.example.com',
            'password' => 'Password123!',
            'role' => 'super-admin',
        ], ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(403);
        $this->assertDatabaseMissing('users', ['email' => 'sneaky@c.example.com']);
    }
}
