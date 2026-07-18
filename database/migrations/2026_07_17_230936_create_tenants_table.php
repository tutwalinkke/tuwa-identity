<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tenants', function (Blueprint $table) {

            $table->id();

            $table->string('name');

            $table->string('domain')
                ->nullable()
                ->unique();

            $table->enum('status', [
                'active',
                'suspended'
            ])
            ->default('active');

            $table->timestamps();

        });
    }


    public function down(): void
    {
        Schema::dropIfExists('tenants');
    }
};
