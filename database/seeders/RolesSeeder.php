<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class RolesSeeder extends Seeder
{
    public function run(): void
    {

        $permissions = [

            'manage system',
            'manage users',
            'manage tenants',
            'view reports',
            'manage billing',
            'manage network',

        ];


        foreach ($permissions as $permission) {

            Permission::firstOrCreate([
                'name' => $permission,
                'guard_name' => 'web'
            ]);

        }


        $roles = [

            'super-admin',
            'tenant-admin',
            'operator',
            'support',
            'customer',

        ];


        foreach ($roles as $role) {

            Role::firstOrCreate([
                'name' => $role,
                'guard_name' => 'web'
            ]);

        }

    }
}
