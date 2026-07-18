<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class UserManagementTest extends TestCase
{
    use RefreshDatabase;

    protected Tenant $tenant;
    protected User $superAdmin;

    protected function setUp(): void
    {
        parent::setUp();

        foreach (['super-admin', 'tenant-admin', 'operator', 'support', 'customer'] as $role) {
            Role::create(['name' => $role, 'guard_name' => 'web']);
        }

        $this->tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test.example.com', 'status' => 'active']);

        $this->superAdmin = User::create([
            'tenant_id' => $this->tenant->id,
            'name' => 'Super Admin',
            'email' => 'super@example.com',
            'phone' => '0700000000',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $this->superAdmin->assignRole('super-admin');
    }

    protected function tokenFor(User $user): string
    {
        return $user->createToken('test')->plainTextToken;
    }

    public function test_super_admin_can_create_user_in_specific_tenant(): void
    {
        $otherTenant = Tenant::create(['name' => 'Other Tenant', 'domain' => 'other.example.com', 'status' => 'active']);
        $token = $this->tokenFor($this->superAdmin);

        $response = $this->postJson('/api/v1/users', [
            'name' => 'New User',
            'email' => 'new@other.example.com',
            'password' => 'Password123!',
            'role' => 'tenant-admin',
            'tenant_id' => $otherTenant->id,
        ], ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(201)
            ->assertJsonPath('user.tenant_id', $otherTenant->id);

        $this->assertDatabaseHas('users', ['email' => 'new@other.example.com', 'tenant_id' => $otherTenant->id]);
    }

    public function test_creating_user_requires_unique_email(): void
    {
        $token = $this->tokenFor($this->superAdmin);

        $response = $this->postJson('/api/v1/users', [
            'name' => 'Duplicate',
            'email' => 'super@example.com',
            'password' => 'Password123!',
            'role' => 'operator',
            'tenant_id' => $this->tenant->id,
        ], ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    public function test_tenant_admin_can_create_operator_in_own_tenant(): void
    {
        $tenantAdmin = User::create([
            'tenant_id' => $this->tenant->id,
            'name' => 'Tenant Admin',
            'email' => 'ta@example.com',
            'phone' => '0700000001',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $tenantAdmin->assignRole('tenant-admin');
        $token = $this->tokenFor($tenantAdmin);

        $response = $this->postJson('/api/v1/users', [
            'name' => 'New Operator',
            'email' => 'operator@example.com',
            'password' => 'Password123!',
            'role' => 'operator',
        ], ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(201)
            ->assertJsonPath('user.tenant_id', $this->tenant->id);
    }

    public function test_operator_cannot_create_users_at_all(): void
    {
        $operator = User::create([
            'tenant_id' => $this->tenant->id,
            'name' => 'Operator',
            'email' => 'op@example.com',
            'phone' => '0700000002',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $operator->assignRole('operator');
        $token = $this->tokenFor($operator);

        $response = $this->postJson('/api/v1/users', [
            'name' => 'Should Not Work',
            'email' => 'blocked@example.com',
            'password' => 'Password123!',
            'role' => 'customer',
        ], ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(403);
        $this->assertDatabaseMissing('users', ['email' => 'blocked@example.com']);
    }

    public function test_updating_user_role_works(): void
    {
        $target = User::create([
            'tenant_id' => $this->tenant->id,
            'name' => 'Target',
            'email' => 'target@example.com',
            'phone' => '0700000003',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $target->assignRole('operator');
        $token = $this->tokenFor($this->superAdmin);

        $response = $this->patchJson("/api/v1/users/{$target->id}/role", [
            'role' => 'support',
        ], ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(200);
        $this->assertTrue($target->fresh()->hasRole('support'));
        $this->assertFalse($target->fresh()->hasRole('operator'));
    }

    public function test_disabling_a_user_revokes_their_tokens_immediately(): void
    {
        $target = User::create([
            'tenant_id' => $this->tenant->id,
            'name' => 'Target',
            'email' => 'target2@example.com',
            'phone' => '0700000004',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $target->assignRole('operator');
        $targetToken = $this->tokenFor($target);

        $preCheck = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$targetToken}"]);
        $preCheck->assertStatus(200);

        $this->app['auth']->forgetGuards();

        $adminToken = $this->tokenFor($this->superAdmin);
        $this->patchJson("/api/v1/users/{$target->id}/status", [
            'status' => 'blocked',
        ], ['Authorization' => "Bearer {$adminToken}"])->assertStatus(200);

        $this->assertSame('blocked', $target->fresh()->status);

        $this->app['auth']->forgetGuards();

        $postCheck = $this->getJson('/api/v1/me', ['Authorization' => "Bearer {$targetToken}"]);
        $postCheck->assertStatus(401);
    }

    public function test_status_must_be_a_valid_enum_value(): void
    {
        $target = User::create([
            'tenant_id' => $this->tenant->id,
            'name' => 'Target',
            'email' => 'target3@example.com',
            'phone' => '0700000005',
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $token = $this->tokenFor($this->superAdmin);

        $response = $this->patchJson("/api/v1/users/{$target->id}/status", [
            'status' => 'not-a-real-status',
        ], ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(422);
    }
}
