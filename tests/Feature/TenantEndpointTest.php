<?php

namespace Tests\Feature;

use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class TenantEndpointTest extends TestCase
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
            'password' => 'Password123!',
            'status' => 'active',
        ]);
        $user->assignRole($role);

        return $user;
    }

    public function test_super_admin_can_fetch_tenant_metadata(): void
    {
        $tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test.example.com', 'status' => 'active']);
        $admin = $this->makeUserWithRole($tenant, 'super-admin', 'admin@example.com');
        $token = $admin->createToken('test')->plainTextToken;

        $response = $this->getJson("/api/v1/tenants/{$tenant->id}", ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(200)
            ->assertJsonPath('tenant.name', 'Test Tenant')
            ->assertJsonStructure(['tenant' => ['id', 'name', 'domain', 'status', 'created_at']]);
    }

    public function test_regular_user_cannot_fetch_tenant_metadata(): void
    {
        $tenant = Tenant::create(['name' => 'Test Tenant', 'domain' => 'test2.example.com', 'status' => 'active']);
        $operator = $this->makeUserWithRole($tenant, 'operator', 'operator@example.com');
        $token = $operator->createToken('test')->plainTextToken;

        $response = $this->getJson("/api/v1/tenants/{$tenant->id}", ['Authorization' => "Bearer {$token}"]);

        $response->assertStatus(403);
    }

    public function test_unauthenticated_request_is_rejected(): void
    {
        $response = $this->getJson('/api/v1/tenants/1');

        $response->assertStatus(401);
    }
}
