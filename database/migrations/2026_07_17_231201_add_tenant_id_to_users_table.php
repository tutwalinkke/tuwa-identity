<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {

            $table->foreignId('tenant_id')
                ->nullable()
                ->after('id')
                ->constrained()
                ->cascadeOnDelete();

            $table->string('phone')
                ->nullable()
                ->after('email');

            $table->enum('status', [
                'active',
                'inactive',
                'blocked'
            ])
            ->default('active');

            $table->timestamp('last_login_at')
                ->nullable();

        });
    }


    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {

            $table->dropForeign(['tenant_id']);

            $table->dropColumn([
                'tenant_id',
                'phone',
                'status',
                'last_login_at'
            ]);

        });
    }
};
