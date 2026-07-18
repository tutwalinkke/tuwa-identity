<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    protected array $manageableRoles = ['operator', 'support', 'customer'];

    protected function assertCanManageUsers(Request $request): void
    {
        if (! $request->user()->hasAnyRole(['super-admin', 'tenant-admin'])) {
            abort(403, 'You do not have permission to manage users.');
        }
    }

    protected function assertCanAssignRole(Request $request, string $role): void
    {
        $actor = $request->user();

        if ($actor->hasRole('super-admin')) {
            return;
        }

        if ($actor->hasRole('tenant-admin') && in_array($role, $this->manageableRoles, true)) {
            return;
        }

        abort(403, 'You are not allowed to assign this role.');
    }

    protected function resolveTargetUser(Request $request, int $id): User
    {
        $actor = $request->user();
        $target = User::findOrFail($id);

        if ($actor->hasRole('super-admin')) {
            return $target;
        }

        if ($actor->hasRole('tenant-admin') && $target->tenant_id === $actor->tenant_id) {
            return $target;
        }

        abort(403, 'You do not have access to this user.');
    }

    public function index(Request $request)
    {
        $this->assertCanManageUsers($request);
        $actor = $request->user();

        $query = User::with('roles');

        if (! $actor->hasRole('super-admin')) {
            $query->where('tenant_id', $actor->tenant_id);
        }

        return response()->json([
            'users' => $query->get(),
        ]);
    }

    public function store(Request $request)
    {
        $this->assertCanManageUsers($request);
        $actor = $request->user();

        $rules = [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'phone' => 'nullable|string|max:255',
            'password' => 'required|string|min:8',
            'role' => 'required|string',
        ];

        if ($actor->hasRole('super-admin')) {
            $rules['tenant_id'] = 'required|exists:tenants,id';
        }

        $validated = Validator::make($request->all(), $rules)->validate();

        $this->assertCanAssignRole($request, $validated['role']);

        $tenantId = $actor->hasRole('super-admin')
            ? $validated['tenant_id']
            : $actor->tenant_id;

        $user = User::create([
            'tenant_id' => $tenantId,
            'name' => $validated['name'],
            'email' => $validated['email'],
            'phone' => $validated['phone'] ?? null,
            'password' => $validated['password'],
            'status' => 'active',
        ]);

        $user->assignRole($validated['role']);

        activity()
            ->causedBy($actor)
            ->performedOn($user)
            ->log('User created');

        return response()->json([
            'user' => $user->load('roles'),
        ], 201);
    }

    public function updateRole(Request $request, int $id)
    {
        $this->assertCanManageUsers($request);

        $target = $this->resolveTargetUser($request, $id);

        $validated = $request->validate([
            'role' => 'required|string',
        ]);

        $this->assertCanAssignRole($request, $validated['role']);

        $target->syncRoles([$validated['role']]);

        activity()
            ->causedBy($request->user())
            ->performedOn($target)
            ->log('User role updated to ' . $validated['role']);

        return response()->json([
            'user' => $target->load('roles'),
        ]);
    }

    public function updateStatus(Request $request, int $id)
    {
        $this->assertCanManageUsers($request);

        $target = $this->resolveTargetUser($request, $id);

        $validated = $request->validate([
            'status' => 'required|in:active,inactive,blocked',
        ]);

        $target->update(['status' => $validated['status']]);

        if ($validated['status'] !== 'active') {
            // Revoke all active sessions immediately when disabling/blocking.
            $target->tokens()->delete();
        }

        activity()
            ->causedBy($request->user())
            ->performedOn($target)
            ->log('User status changed to ' . $validated['status']);

        return response()->json([
            'user' => $target->fresh(),
        ]);
    }
}
